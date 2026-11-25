#!/usr/bin/env python3
"""The corpus that go-pfcp and the crate read, for the test `go_pfcp`: a message a line,
its name and its octets in hexadecimal, each message once.

    python3 tests/go-pfcp/corpus.py OUT.tsv SOURCE...

A SOURCE is a directory of messages, one a file, as fuzz/seeds/messages and the corpus of
a fuzz target are, or the file that tests/go-pfcp-vectors.py writes of go-pfcp's vectors.
"""
import os
import sys

if len(sys.argv) < 3:
    sys.exit(__doc__)
out, sources = sys.argv[1], sys.argv[2:]
seen, rows = set(), []


def add(name, octets):
    if octets and octets not in seen:
        seen.add(octets)
        rows.append((name, octets.hex()))


for source in sources:
    if os.path.isdir(source):
        label = os.path.normpath(source)
        for name in sorted(os.listdir(source)):
            with open(os.path.join(source, name), 'rb') as f:
                add(f'{label}/{name}', f.read())
    else:
        for line in open(source, encoding='utf-8'):
            file, description, octets = line.rstrip('\n').split('\t')
            add(f'go-pfcp/{file}/{description}', bytes.fromhex(octets))
with open(out, 'w', encoding='utf-8') as f:
    for name, octets in rows:
        f.write(f'{name}\t{octets}\n')
print(len(rows), 'messages')
