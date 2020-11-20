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

passwords = [
    ("x", "1"),
    ("want", "epuu7Aeja9"),
    ("emerge", "zexae2Moo2"),
    ("question", "dahTho9Thai5yiasie1c"),
    ("quick fiber estate ripple phrase", "huu4aeju2gooth1iS6ai")
]

password_names = [name for name, _ in passwords]

auto = Automaton()
client = Client(auto)

# Test password insertion
assert client.get_size() == 0
for i, (name, password) in enumerate(passwords):
    auto.actions = "rb"
    client.add(name, password)
    assert client.get_size() == i+1

# List password names
assert set(client.get_names()) == set(password_names)

# Test password retrieval
for name, password in passwords:
    auto.actions = "rb"
    assert password == client.get_by_name(name)

# Test password removal
removal_order = [name for name, _ in passwords]
random.shuffle(removal_order)
names = set(password_names)
for name in removal_order:
    auto.actions = "rb"
    client.delete_by_name(name)
    names.remove(name)
    assert set(client.get_names()) == names
assert client.get_size() == 0

# Test Clear APDU
for name, password in passwords:
    auto.actions = "rb"
    client.add(name, password)
assert client.get_size() == len(passwords)
auto.actions = "bb"
client.clear()
assert client.get_size() == 0

