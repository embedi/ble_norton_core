"""Scraping information about device from service web page."""

import functools
import re
import sys
from urllib.error import URLError
from urllib.request import urlopen


def search_on_page(func):
    """Connect to web page and search needed info."""

    @functools.wraps(func)
    # pylint: disable=inconsistent-return-statements
    # pylint: disable=protected-access
    def wrapper(self, *args, **kwargs):
        """Wrapper for universal searching info."""
        if self._body:
            return func(self, *args, **kwargs)
        else:
            print("[+] Searching info on web page...")
            for r_url in self._root_urls:
                print("[+]\t try {}".format(r_url + self._page_url))
                try:
                    response = urlopen(r_url + self._page_url)
                    if response.status != 200:
                        continue
                    self._body = response.read()
                    if b"Service not available" in self._body:
                        print("Please reboot router for access to hidden web page.")
                        sys.exit(2)
                    return func(self, *args, **kwargs)
                except URLError as err:
                    print("[-] error: {}".format(err))
                    continue
            print("Error: getting info from web page.")
            sys.exit(2)

    return wrapper


class WebInfo:
    """Class for getting info from engineering web page of Norton Core Router."""

    def __init__(self):
        self._root_urls = ["http://norton.core", "http://172.16.0.1", "http://172.17.0.1"]
        self._page_url = "/info.php"
        self._body = None
        self.bt_mac = None
        self.serial_number = None

    @search_on_page
    def search_bt_mac(self):
        """
        :return: Found BT MAC address on web page.

        """

        if self.bt_mac:
            return self.bt_mac
        else:
            match = re.search(b"BT MAC Address:(?P<BT_MAC>[A-Z0-9:]+)\n", self._body)
            if not match:
                print("BT MAC Address not found, please check {} for details.".format(
                    r_url + self._page_url)) # pylint: disable=undefined-variable
                sys.exit(2)
            self.bt_mac = match.group("BT_MAC").decode("utf-8")
            print("[+] BT MAC address was obtained.")
            return self.bt_mac

    @search_on_page
    def search_serial_number(self):
        """
        :return: Found device serial number on web page.

        """

        if self.serial_number:
            return self.serial_number
        else:
            match = re.search(b"Device Serial No:(?P<serial_number>\w+)\n", self._body)
            if not match:
                print("Device Serial Number not found, please check {} for details.".format(
                    r_url + self._page_url)) # pylint: disable=undefined-variable
                sys.exit(2)
            self.serial_number = match.group("serial_number").decode("utf-8")
            print("[+] Device Serial Number was obtained.")
            return self.serial_number
