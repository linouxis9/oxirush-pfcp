#!/usr/bin/env python3
"""The fixtures of the test `spec`, from the document that the crate follows: TS 29.244
V19.6.0 (2025-06), as the 3GPP archive has it.

    python3 tests/spec/extract.py 29244-j60.zip     # the archive, fetched already
    python3 tests/spec/extract.py --fetch           # fetched from the 3GPP archive

The archive is checked against its SHA-256, and the fixtures are written beside this
script:

    message-types.tsv   Table 7.3-1: the message types and the interfaces that have them
    ie-types.tsv        Table 8.1.2-1: the IE types, their references and their lengths
    tables.tsv          the tables of clause 7, one row each
    layouts.tsv         the figures of clause 8.2: their clause, the type that they say, and
                        the names of their flags and fields, in order
    value-tables.tsv    the tables of clause 8.2 that name values, or bits as octet/bit
    clause-6.tsv        the headings of clause 6, and how many sentences each has that say
                        "shall" or "should": the requirements that requirements.tsv lists

Only the standard library is used. The cells are written as the document has them, with
their spaces made single: what the crate does differently is in errata.tsv.
"""
import hashlib
import io
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

URL = 'https://www.3gpp.org/ftp/Specs/archive/29_series/29.244/29244-j60.zip'
SHA256 = '5972efec3a61a40c4da7534861495e43f88cb94315cb51c5a85997b50636c1c3'
HERE = os.path.dirname(os.path.abspath(__file__))
W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
INTERFACES = ['Sxa', 'Sxb', 'Sxc', 'N4', 'N4mb']


def archive():
    if sys.argv[1:] == ['--fetch']:
        request = urllib.request.Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
        data = urllib.request.urlopen(request, timeout=60).read()
    elif len(sys.argv) == 2:
        data = open(sys.argv[1], 'rb').read()
    else:
        sys.exit(__doc__)
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        sys.exit(f'the archive has SHA-256 {digest}, and V19.6.0 has {SHA256}')
    with zipfile.ZipFile(io.BytesIO(data)) as outer:
        docx = next(name for name in outer.namelist() if name.endswith('.docx'))
        with zipfile.ZipFile(io.BytesIO(outer.read(docx))) as inner:
            return ET.fromstring(inner.read('word/document.xml'))


def text(element):
    out = []
    for node in element.iter():
        if node.tag == W + 't':
            out.append(node.text or '')
        elif node.tag in (W + 'tab', W + 'br', W + 'cr'):
            out.append(' ')
    return clean(''.join(out))


def clean(value):
    value = value.replace(' ', ' ').replace('’', "'").replace('‘', "'")
    return re.sub(r'\s+', ' ', value).strip()


def blocks(body):
    """The paragraphs, as (style, text), and the tables, as rows of (text, span)."""
    for child in body:
        if child.tag == W + 'p':
            style = child.find(f'{W}pPr/{W}pStyle')
            value = text(child)
            if value:
                yield 'p', (style.get(W + 'val') if style is not None else '', value)
        elif child.tag == W + 'tbl':
            rows = []
            for row in child.findall(W + 'tr'):
                cells = []
                for cell in row.findall(W + 'tc'):
                    span = cell.find(f'{W}tcPr/{W}gridSpan')
                    paragraphs = [text(p) for p in cell.iter(W + 'p')]
                    cells.append((' / '.join(p for p in paragraphs if p), int(span.get(W + 'val')) if span is not None else 1))
                rows.append(cells)
            yield 'tbl', rows
        elif child.tag == W + 'sdt':
            content = child.find(W + 'sdtContent')
            if content is not None:
                yield from blocks(content)


def interfaces(cells):
    return ' '.join(name for name, cell in zip(INTERFACES, cells) if 'X' in cell.upper())


def without_notes(name):
    name = re.sub(r'(?:,?\s*\((?:see |See )?NOTE[^)]*\))+', '', name)
    return clean(re.sub(r',\s*see NOTE \d+', '', name))


def main():
    body = archive().find(W + 'body')
    heading, caption = '', None
    message_types, ie_types, tables, layouts, values, clause6 = [], [], [], [], [], []
    for kind, block in blocks(body):
        if kind == 'p':
            style, value = block
            if style.startswith('Heading') or re.match(r'^8\.2\.\d+ [A-Z]', value) and style == '':
                heading = value
                if re.match(r'^6(\.\d+)* ', value):
                    clause6.append(value.split(' ', 1) + [0])
            elif clause6 and re.match(r'^6(\.\d+)* ', heading):
                clause6[-1][2] += len(requirements(value))
            caption = value if style == 'TH' else None
            continue
        if clause6 and re.match(r'^6(\.\d+)* ', heading):
            clause6[-1][2] += sum(len(requirements(cell)) for row in block for cell, _ in row)
        rows = [[cell for cell, _ in row] for row in block]
        spans = [[span for _, span in row] for row in block]
        title, caption = caption, None
        if title and title.startswith('Table 7.3-1'):
            for row in rows:
                if re.fullmatch(r'\d+', row[0]) and row[1] != 'Reserved':
                    message_types.append([row[0], row[1], interfaces(row[2:7])])
        elif title and title.startswith('Table 8.1.2-1'):
            for row in rows[1:]:
                if re.fullmatch(r'\d+(?: to \d+)?', row[0]):
                    ie_types.append(row[:4] + [''] * (4 - len(row[:4])))
        elif title and re.search(r'Table 7\.[\d.]+-\d+\.?:', title):
            number = re.search(r'Table (7\.[\d.]+-\d+)', title).group(1)
            ie_type = ''
            entry = ['table', number, title.split(':', 1)[1].strip() if ':' in title else title, heading, '']
            tables.append(entry)
            for row in rows:
                joined = ' '.join(row)
                found = re.search(r'=\s*(\d+)\s*\(decimal\)', joined)
                if found and not ie_type and row[0].lower().startswith('octet'):
                    entry[4] = ie_type = found.group(1)
                elif re.match(r'Same IEs', row[0]):
                    tables.append(['same', number, re.search(r'Table (7\.[\d.]+-\d+)', row[0]).group(1)])
                elif len(row) >= 9 and row[1] in ('M', 'C', 'O'):
                    tables.append(['row', number, without_notes(row[0]), row[1], interfaces(row[3:8]), without_notes(row[8])])
        elif title and re.match(r'Table 8\.2\.\d+[.-]\d+', title):
            number = re.match(r'Table (8\.2\.\d+[.-]\d+)', title).group(1)
            values.extend(value_rows(number, title.split(':', 1)[1].strip(), rows))
        elif re.match(r'^8\.2\.\d+ ', heading):
            figure = members(rows, spans)
            if figure:
                layouts.append([heading.split(' ', 1)[0]] + figure)
    write('message-types.tsv', ['value', 'name', 'interfaces'], message_types)
    write('ie-types.tsv', ['type', 'name', 'reference', 'length'], ie_types)
    write('tables.tsv', ['table|row|same', 'table', 'name, or the name of the row', 'heading, or presence', 'IE type, or interfaces', 'IE type'], tables)
    write('layouts.tsv', ['clause', 'type in the figure', 'fields'], layouts)
    write('value-tables.tsv', ['table', 'title', 'value', 'name'], values)
    write('clause-6.tsv', ['clause', 'title', 'requirements'], [[c, t, str(n)] for c, t, n in clause6])


def requirements(paragraph):
    """The sentences of a paragraph that say "shall" or "should", in order."""
    sentences = re.split(r'(?<!i\.e\.)(?<!e\.g\.)(?<=[.;:])\s+(?=[A-Z(-])', paragraph)
    return [sentence for sentence in sentences if re.search(r'\b(shall|should)\b', sentence)]


def members(rows, spans):
    """The IE type of a figure of clause 8.2, and the names of its flags and fields."""
    ie_type, names = None, []
    for row, span in zip(rows, spans):
        cells = [(cell, width) for cell, width in zip(row, span)]
        while cells and cells[0][0] in ('', '.'):
            cells = cells[1:]
        if not cells or cells[0][0] in ('Bits', 'Octets'):
            continue
        joined = ' '.join(cell for cell, _ in cells)
        found = re.search(r'Type\s*=\s*(\d+)', joined)
        if found:
            ie_type = ie_type or found.group(1)
            continue
        if re.search(r'Length\s*=', joined) or 'explicitly specified' in joined:
            continue
        for cell, _ in cells[1:]:
            name = without_notes(cell)
            if name and not re.fullmatch(r'(?i)spare|\.\.\.|…|\d+', name):
                names.append(name)
    return [ie_type] + [' | '.join(names)] if ie_type else None


def value_rows(number, title, rows):
    head = [cell.lower() for cell in rows[0]]
    if len(rows[0]) == 1:   # units in prose, one cell: "0 0 0 value is incremented in multiples of 2 seconds"
        out = []
        for bits, words in re.findall(r'([01] [01] [01]) ([^/]+)', rows[0][0]):
            words = re.sub(r'^value is incremented in multiples of ', '', words.strip())
            words = 'infinite' if words == 'value indicates that the timer is infinite' else words
            out.append([number, title, str(int(bits.replace(' ', ''), 2)), words])
        return out
    numbers = [i for i, cell in enumerate(head) if 'decimal' in cell]
    if not numbers:   # a table of bits, as Table 8.2.25-1 of the features: octet/bit
        return [[number, title, row[0], without_notes(row[1])] for row in rows[1:]
                if re.fullmatch(r'\d+/\d+', row[0])]
    at = numbers[0]
    name_at = head.index('meaning') if 'meaning' in head else 1 - at
    out = []
    for row in rows[1:]:
        if len(row) <= max(at, name_at) or row[0].startswith('NOTE'):
            continue
        value, name = row[at], without_notes(row[name_at])
        name = clean(re.sub(r'\s+– see .*$|\s*\(see clause .*$', '', name)).rstrip('.')
        if re.fullmatch(r'\d+', value) and not re.match(r'(?i)spare|for future use|<?reserved', name):
            out.append([number, title, value, name])
    return out


def write(name, head, rows):
    with open(os.path.join(HERE, name), 'w', encoding='utf-8') as out:
        out.write('# ' + '\t'.join(head) + '\n')
        for row in rows:
            out.write('\t'.join(row) + '\n')
    print(f'{name}: {len(rows)} lines')


main()
