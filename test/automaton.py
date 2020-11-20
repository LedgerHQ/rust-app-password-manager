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

class Automaton:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(("localhost", 9999))
        self.sock_buttons = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_buttons.connect(("localhost", 9998))
        self.actions = ''

    def transmit(self, apdu: bytes):
        self.sock.send(len(apdu).to_bytes(4, 'big') + apdu)

    def receive(self) -> bytes:
        data = self.__recv_all(4)
        size = int.from_bytes(data, 'big')
        result = self.__recv_all(size+2)
        return result

    def exchange(self, apdu: bytes) -> bytes:
        """
        Send an APDU and return the response. Process button press indicated in
        self.actions during the APDU processing of the device.
        Satus word is removed from the response, in order to have the same
        interface as ledgerblue lib.
        """
        self.transmit(apdu)
        if len(self.actions):
            for c in self.actions:
                if c == 'r':
                    self.press_right()
                elif c == 'l':
                    self.press_left()
                elif c == 'b':
                    self.press_both()
            self.actions = ''
        resp = self.receive()
        assert resp[-2:] == b'\x90\x00'
        return resp[:-2]
        
    def __recv_all(self, n) -> bytes:
        result = bytes()
        while n > 0:
            chunck = self.sock.recv(n)
            result += chunck
            n -= len(chunck)
        return result

    def press_left(self):
        sleep(0.2)
        self.sock_buttons.write('L'.encode())
        sleep(0.2)
        self.sock_buttons.write('l'.encode())
    
    def press_right(self):
        sleep(0.2)
        self.sock_buttons.send('R'.encode())
        sleep(0.2)
        self.sock_buttons.send('r'.encode())

    def press_both(self):
        sleep(0.2)
        self.sock_buttons.send('RL'.encode())
        sleep(0.2)
        self.sock_buttons.send('rl'.encode())
