#!/usr/bin/env python3
"""The seeds of the fuzz targets, from the messages that tests/captures has: each message
for `decode` and `tree`, and for `node` each message as a piece of input that delivers it
to the UPF and to the SMF.

    python3 fuzz/seeds.py      # writes fuzz/seeds/messages and fuzz/seeds/node

CI copies them into the corpus of each target before it fuzzes.
"""
import hashlib
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CAPTURES = os.path.join(HERE, '..', 'tests', 'captures', 'messages.tsv')


def write(directory, data):
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, hashlib.sha1(data).hexdigest()), 'wb') as out:
        out.write(data)


def main():
    messages = []
    for line in open(CAPTURES, encoding='utf-8'):
        if line.startswith('#') or not line.strip():
            continue
        messages.append(bytes.fromhex(line.rstrip('\n').split('\t')[5]))
    for message in messages:
        write(os.path.join(HERE, 'seeds', 'messages'), message)
        # The first octet: bit 1 the node (0 the SMF, 1 the UPF), time steps in bits 4 to 7.
        if 0xa5 not in message:
            write(os.path.join(HERE, 'seeds', 'node'), bytes([0x01]) + message + bytes([0xa5, 0x08]) + message)
    print(len(messages), 'messages')


main()
