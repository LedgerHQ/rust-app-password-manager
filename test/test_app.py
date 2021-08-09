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

from automaton import Automaton
from nanopass import Client
import random

def subtest_password_list(client, passwords):
    """ Test password name listing. """
    entries = client.get_names()
    assert (set(client.get_names()) ==
        set(name for (name, _, _) in passwords))

def subtest_has_name(client, passwords):
    """ Test the HasName APDU command """
    for name, _, _ in passwords:
        assert client.has_name(name)
    assert not client.has_name("undefined")

def subtest_password_retrieval(client, auto, passwords):
    """ Verify the correctness of login and password values. """
    for name, login, password in passwords:
        auto.actions = "rb"
        login2, password2 = client.get_by_name(name)
        assert login == login2
        assert password == password2

def subtest_clear(client, auto, passwords):
    for name, login, password in passwords:
        auto.actions = "rb"
        client.add(name, login, password)
    assert client.get_size() == len(passwords)
    auto.actions = "bb"
    client.clear()
    assert client.get_size() == 0

def test_app():
    passwords = [
        ("x", "", "1"),
        ("want", "a", "epuu7Aeja9"),
        ("emerge", "bamboo", "zexae2Moo2"),
        ("question", "predict", "dahTho9Thai5yiasie1c"),
        ("quick fiber estate ripple phrase", "topic", "huu4aeju2gooth1iS6ai")
    ]

    auto = Automaton()
    client = Client(auto)

    # Test password insertion
    assert client.get_size() == 0
    for i, (name, login, password) in enumerate(passwords):
        auto.actions = "rb"
        client.add(name, login, password)
        assert client.get_size() == i+1

    subtest_password_list(client, passwords)
    subtest_has_name(client, passwords)
    subtest_password_retrieval(client, auto, passwords)

    # Export in plain text and also in encrypted form
    # Do this before password removal testing
    auto.actions = "brb"
    export_plain = client.export(encrypt=False)
    auto.actions = "b"
    export_encrypted = client.export()

    # Test password removal
    removal_order = [name for name, _, _ in passwords]
    random.shuffle(removal_order)
    names = set(removal_order)
    for name in removal_order:
        auto.actions = "rb"
        client.delete_by_name(name)
        names.remove(name)
        assert set(client.get_names()) == names
    assert client.get_size() == 0

    # Test import plain
    subtest_clear(client, auto, passwords)
    auto.actions = ";b"
    client.import_("1.1.0", export_plain, encrypted=False)
    subtest_password_list(client, passwords)
    subtest_password_retrieval(client, auto, passwords)

    # Test import encrypted
    subtest_clear(client, auto, passwords)
    auto.actions = ";b"
    client.import_("1.1.0", export_encrypted, encrypted=True)
    subtest_password_list(client, passwords)
    subtest_password_retrieval(client, auto, passwords)

