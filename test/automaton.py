#!/usr/bin/python3
#
# Copyright 2020 Ledger SAS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from nanopass import Client
from time import sleep
from binascii import hexlify
import socket
import os.path
from speculos.client import SpeculosClient

class Automaton(SpeculosClient):
    def __init__(self):
        app_path = os.path.join(
            os.path.dirname(__file__), "..", "target", "thumbv6m-none-eabi",
            "release", "nanopass")
        super().__init__(app_path)
        self.actions = ''
        self.cla = 0x80

    def apdu_exchange(self, ins: int, data: bytes=b"", p1: int=0, p2:int=0
        ) -> bytes:
        """
        Send an APDU and return the response. Process button press indicated in
        self.actions during the APDU processing of the device.
        API matches ledgerwallet library.
        """
        apdu = bytes([self.cla, ins, p1, p2, len(data)]) + data
        with super().apdu_exchange_nowait(self.cla, ins, data, p1=p1, p2=p2) as response:
            while len(self.actions):
                # Wait to be sure speculos has enough time to process
                sleep(0.1)
                c = self.actions[0]
                self.actions = self.actions[1:]
                if c == 'r':
                    self.press_right()
                elif c == 'l':
                    self.press_left()
                elif c == 'b':
                    self.press_both()
                elif c == ';':
                    # Next actions for next APDU
                    break;
            return response.receive()
        
    def press(self, button: str):
        self.press_and_release(button)

    def press_left(self):
        self.press("left")
    
    def press_right(self):
        self.press("right")

    def press_both(self):
        self.press("both")

