"""Protocol of communication.

This module contain classes for generating and encrypting messages.
"""

import binascii
import hmac
import math
from hashlib import pbkdf2_hmac, sha256

from Crypto.Cipher import AES


class Protocol:
    """Protocol encoding/decoding for Norton Core WiFi router."""

    @staticmethod
    def encode_set_setting(setting_type, value, serial_number, init_vec):
        """Construct a message to set a setting.

        :param setting_type: Setting type, see paper for details.
        :param value: Value of the setting.
        :param serial_number: Device serial number, uses as key for encryption.
        :param init_vec: IV for encryption.
        :return: Constructed message.

        """
        enc = Encryption(serial_number, init_vec)
        data_set = DataSet(setting_type, value, enc)
        return data_set.get_whole_request()

    @staticmethod
    def encode_request_unlock(serial_number, init_vec):
        """Construct a message to unlock Norton Core Secure Router BLE channel. Format of message:
        [type_of_message, length_of_data, nonce] ([0x06, 0x10, nonce]).

        :param serial_number: Device serial number, uses as key for encryption.
        :param init_vec: IV for encryption.
        :return: Constructed message.

        """

        enc = Encryption(serial_number, init_vec)
        msg = bytearray([0x06, 0x10]) + enc.get_nonce()
        return msg

    @staticmethod
    def encode_request_iv(protocol_version):
        """Construct a message to get IV for encryption.

        :param protocol_version: Protocol version of BLE communication.
        :return: Constructed message.

        """

        protocol_version = float(protocol_version)
        minor_ver, major_ver = math.modf(protocol_version)
        return bytearray([0x00, int(major_ver), int(minor_ver * 10)])

    @staticmethod
    def decode_ack(buffer):
        """Decode a Ack response.

        :param buffer: Message (Ack response) for decoding.
        :return: Length of sent data.

        """

        return buffer[2]

    @staticmethod
    def decode_iv(buffer):
        """Decode a message with IV.

        :param buffer: Message for decoding.
        :return: Initialization vector for encryption.

        """

        return buffer[2:18]


class DataSet:
    """Class for generating encrypted message for set a setting: username, password, IP, DNS and
    etc.

    """

    _type_request = 0x01

    def __init__(self, setting_type, value, encryptor):
        """
        :param setting_type: Type of setting.
        :param value: Value of setting.
        :param encryptor: Encryption object for encrypting message.

        """

        value = bytes(value, 'utf-8')
        self._setting_type = setting_type
        self._data = value
        self._data += sha256(value).digest()[:4]
        self._data += self._get_padding(self._data)
        self._data = encryptor.encrypt(self._data)

        self._total_len = len(self._data)
        self._sent_len = 0

    def get_chunk_request(self):
        """Get part of request. Uses for testing.

        :return: Chunk of request.

        """

        if self._sent_len == self._total_len:
            return None
        packet_len = min(self._total_len - self._sent_len, 13)

        packet = bytearray(2 + 3)
        packet[0] = self._type_request
        packet[1] = packet_len + 3 | 0x80
        packet[2] = packet_len + self._sent_len
        packet[3] = self._total_len
        packet[4] = self._setting_type

        msg = self._data[self._sent_len:self._sent_len + packet_len]
        packet += msg

        self._sent_len += packet_len

        return packet

    def get_whole_request(self):
        """Get whole request without splitting.

        :return: Whole request.

        """

        request = bytearray()
        chunk_request = self.get_chunk_request()
        while chunk_request:
            request += chunk_request
            chunk_request = self.get_chunk_request()

        return request

    @staticmethod
    def _get_padding(data):
        length = 16 - (len(data) % 16)
        return bytes([length]) * length


class Encryption:
    """Class uses for getting nonce, keys and encrypt messages."""

    def __init__(self, serial_number, iv):
        """
        :param serial_number: Device serial number, uses as key.
        :param iv: Initialization vector.

        """

        self._pwd = bytes(serial_number, 'utf-8')
        self._iv = iv
        self._hmac = hmac.new(self._iv, self._pwd, sha256).digest()[-16:]
        self._dk = pbkdf2_hmac('sha256', self._pwd, self._iv, 1000, 16)

    def __str__(self) -> str:
        return "Enc{{\npwd: {}\
        \niv: {}\
        \nhmac: {}\
        \ndk: {}\
        \n}}".format(self._pwd,
                     binascii.hexlify(self._iv),
                     binascii.hexlify(self._hmac),
                     binascii.hexlify(self._dk))

    def get_nonce(self):
        """Get nonce (HMAC) for unlocking Norton Core Router.

        :return: Generated HMAC.

        """

        return self._hmac

    def encrypt(self, data):
        """Encrypt data with AES, key - device serial number.

        :param data: Plain text data.
        :return: Encrypted data.

        """

        aes_enc = AES.new(self._dk, AES.MODE_CBC, bytes(self._iv))
        return aes_enc.encrypt(data)
