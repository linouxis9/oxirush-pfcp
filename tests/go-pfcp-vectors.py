#!/usr/bin/env python3
"""The test vectors of go-pfcp, for the test of `PFCP_VECTORS`: each Serialized message of
go-pfcp's message tests, with its file and its description.

    python3 tests/go-pfcp-vectors.py GO_PFCP_DIR OUT.tsv
    PFCP_VECTORS=OUT.tsv cargo test --all-features --test codec other_vectors -- --nocapture

GO_PFCP_DIR is go-pfcp at the version that tests/README.md names, as
`go mod download -json github.com/wmnsk/go-pfcp@v0.0.24` gives its "Dir". The vectors are
not committed: they are go-pfcp's.
"""
import os
import re
import sys

if len(sys.argv) != 3:
    sys.exit(__doc__)
root, out = sys.argv[1], sys.argv[2]
rows = []
for name in sorted(os.listdir(os.path.join(root, 'message'))):
    if not name.endswith('_test.go'):
        continue
    text = open(os.path.join(root, 'message', name), encoding='utf-8').read()
    for m in re.finditer(r'Description:\s*"([^"]*)".*?Serialized:\s*\[\]byte\{(.*?)\n\s*\},', text, re.S):
        body = re.sub(r'//[^\n]*', '', m.group(2))
        octets = re.findall(r'0x([0-9a-fA-F]{2})', body)
        rows.append((name, m.group(1), ''.join(octets).lower()))
with open(out, 'w') as f:
    for row in rows:
        f.write('\t'.join(row) + '\n')
print(len(rows), 'vectors')
