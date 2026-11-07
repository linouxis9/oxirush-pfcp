#!/usr/bin/env python3
"""The fixtures of the test `spec`, from the document that the crate follows: TS 29.244
V19.6.0 (2026-06), as the 3GPP archive has it.

    python3 tests/spec/extract.py 29244-j60.zip     # the archive, fetched already
    python3 tests/spec/extract.py --fetch           # fetched from the 3GPP archive

The archive is checked against its SHA-256, and the fixtures are written beside this
script:

    message-types.tsv   Table 7.3-1: the message types and the interfaces that have them
    ie-types.tsv        Table 8.1.2-1: the IE types, their references and their lengths
    tables.tsv          the tables of clause 7, one row each, and whether the comment of a
                        row says that several IEs of it may be there, and how many when it
                        says
    layouts.tsv         the figures of clause 8.2: their clause, the type that they say, and
                        the names of their flags and fields, in order
    figures.tsv         the place of each flag and field of those figures: the octets of its
                        row, its lowest bit and how many bits it has
    conditions.tsv      the sentences of clause 8.2 that make a field there or not as a flag
                        is set or not: the flag, whether it is set, the field, whether it is
                        there
    flag-sentences.tsv  the sentences of clause 8.2 that say which flags of an IE are set
                        together: "at least one", "one and only one", "only one of", "may
                        only be set", "shall be set to "1" if the ... flag is set", "shall
                        not be set", "either ... shall be set" or "exclusive", with a value
                        ("if ... is 1, then the ... flags shall be set"), or always ("this
                        bit shall be set to "1"."), by their clause and their number in it,
                        which flag-rules.tsv lists with the rule that checks each
    value-tables.tsv    the tables of clause 8.2 that name values, or bits as octet/bit; a
                        value that a table reserves is named <reserved>
    read-as.tsv         the values of those tables that a receiver reads as another: the
                        table, the values, and what they are read as, in the words of the
                        document
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
    """The paragraphs, as (style, text), and the tables, as rows of (text, span), with the
    widths of the cells of each row."""
    for child in body:
        if child.tag == W + 'p':
            style = child.find(f'{W}pPr/{W}pStyle')
            value = text(child)
            if value:
                yield 'p', (style.get(W + 'val') if style is not None else '', value)
        elif child.tag == W + 'tbl':
            rows, widths = [], []
            # A cell merged with the one above it (vMerge) has the text of that one.
            above = {}
            for row in child.findall(W + 'tr'):
                cells, sizes = [], []
                before = row.find(f'{W}trPr/{W}gridBefore')
                column = int(before.get(W + 'val')) if before is not None else 0
                for cell in row.findall(W + 'tc'):
                    span = cell.find(f'{W}tcPr/{W}gridSpan')
                    width = cell.find(f'{W}tcPr/{W}tcW')
                    merged = cell.find(f'{W}tcPr/{W}vMerge')
                    paragraphs = [text(p) for p in cell.iter(W + 'p')]
                    value = ' / '.join(p for p in paragraphs if p)
                    if merged is not None and merged.get(W + 'val') != 'restart' and not value:
                        value = above.get(column, '')
                    above[column] = value
                    span = int(span.get(W + 'val')) if span is not None else 1
                    cells.append((value, span))
                    sizes.append(int(width.get(W + 'w')) if width is not None and width.get(W + 'type', 'dxa') == 'dxa' else None)
                    column += span
                rows.append(cells)
                widths.append(sizes)
            yield 'tbl', (rows, widths)
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
    read = []
    figures, conditions, flags = [], [], []
    # The fields of octets of the figure of the clause, by name and by their octets.
    fields, labels = [], {}
    for kind, block in blocks(body):
        if kind == 'p':
            style, value = block
            if style.startswith('Heading') or re.match(r'^8\.2\.\d+ [A-Z]', value) and style == '':
                heading = value
                fields, labels = [], {}
                if re.match(r'^6(\.\d+)* ', value):
                    clause6.append(value.split(' ', 1) + [0])
            elif clause6 and re.match(r'^6(\.\d+)* ', heading):
                clause6[-1][2] += len(requirements(value))
            elif re.match(r'^8\.2\.\d+ ', heading):
                conditions.extend([heading.split(' ', 1)[0]] + relation for relation in relations(value, fields, labels))
                clause = heading.split(' ', 1)[0]
                for phrase in flag_sentences(value):
                    flags.append([clause, str(sum(row[0] == clause for row in flags) + 1), phrase])
            caption = value if style == 'TH' else None
            continue
        block, widths = block
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
                    several = repetition(row[2])
                    tables.append(['row', number, without_notes(row[0]), row[1], interfaces(row[3:8]), without_notes(row[8]), several])
        elif title and re.match(r'Table 8\.2\.\d+[.-]\d+', title):
            number = re.match(r'Table (8\.2\.\d+[.-]\d+)', title).group(1)
            values.extend(value_rows(number, title.split(':', 1)[1].strip(), rows))
            read.extend(read_as(number, rows))
        elif re.match(r'^8\.2\.\d+ ', heading):
            figure = members(rows, spans)
            if figure:
                layouts.append([heading.split(' ', 1)[0]] + figure)
                found = places(block, widths)
                figures.extend([heading.split(' ', 1)[0]] + place for place in found)
                fields = [name for _, name, _, bits in found if bits == '8']
                labels = {re.sub(r'\s+', '', octets): name for octets, name, _, bits in found if bits == '8'}
    write('message-types.tsv', ['value', 'name', 'interfaces'], message_types)
    write('ie-types.tsv', ['type', 'name', 'reference', 'length'], ie_types)
    write('tables.tsv', ['table|row|same', 'table', 'name, or the name of the row', 'heading, or presence', 'IE type, or interfaces', 'IE type', 'once, several, or how many'], tables)
    write('layouts.tsv', ['clause', 'type in the figure', 'fields'], layouts)
    write('figures.tsv', ['clause', 'octets', 'name', 'lowest bit', 'bits'], figures)
    write('conditions.tsv', ['clause', 'flag', 'set', 'field', 'there'], conditions)
    write('flag-sentences.tsv', ['clause', 'n', 'phrase'], flags)
    write('value-tables.tsv', ['table', 'title', 'value', 'name'], values)
    write('read-as.tsv', ['table', 'values', 'read as'], read)
    write('clause-6.tsv', ['clause', 'title', 'requirements'], [[c, t, str(n)] for c, t, n in clause6])


def repetition(comment):
    """Whether a comment lets several IEs of its row be there, and how many when it says:
    "up to 16 times", "Two IEs with the same IE type"."""
    if not SEVERAL.search(comment):
        return 'once'
    found = BOUND.search(comment)
    if found:
        word = (found.group(1) or found.group(2)).lower()
        return str(NUMBERS.get(word) or int(word))
    return 'several'


# The number of IEs of a row that its comment says.
BOUND = re.compile(r'(?i)\bup to (\d+|two|three|four) (?:IEs|times)\b|\b(two|three|four) IEs with the same\b')
NUMBERS = {'two': 2, 'three': 3, 'four': 4}

# The words of a comment that let several IEs of a row be there.
SEVERAL = re.compile(r'(?i:several IEs?\b|several .{0,30}IEs|represent a list|two IEs|more than one IE|IEs? with the same (?:IE )?type|may be repeated|up to \d+ (?:IEs|times)|several instances|for each PDR\b|list of all)')


def places(rows, widths):
    """The flags and fields of a figure of clause 8.2, each with the octets of its row, its
    lowest bit and its number of bits: the bits are those whose cells of the row of bit
    numbers, by their widths, have their middle within the field's cell."""
    header = next((at for at, row in enumerate(rows) if any(cell == 'Octets' for cell, _ in row)), None)
    if header is None:
        return []
    def edges(row, sizes, spans_of):
        at, out = 0, []
        for (cell, span), size in zip(row, sizes):
            width = size if size is not None else spans_of * span
            out.append((cell, at, at + width))
            at += width
        return out
    usable = all(size is not None for size in widths[header])
    middles = {}
    for cell, start, end in edges(rows[header], widths[header] if usable else [None] * len(rows[header]), 1):
        if re.fullmatch(r'[1-8]', cell):
            middles[int(cell)] = (start + end) / 2
    if len(middles) != 8:
        return []
    out = []
    for row, sizes in zip(rows[header + 1:], widths[header + 1:]):
        sizes = sizes if usable and all(size is not None for size in sizes) else [None] * len(row)
        cells = edges(row, sizes, 1)
        label = next(((cell, end) for cell, _, end in cells if cell and cell != '.'), None)
        if label is None or re.search(r'Type\s*=|Length\s*=', ' '.join(cell for cell, _, _ in cells)):
            continue
        octets, after = label
        for cell, start, end in cells:
            name = without_notes(cell)
            if start < after or not name or 'explicitly specified' in name or re.fullmatch(r'(?i)spare|\.\.\.|…|\d+', name):
                continue
            bits = sorted(bit for bit, middle in middles.items() if start <= middle < end)
            if bits:
                out.append([octets, name, str(bits[0]), str(len(bits))])
    return out


def relations(paragraph, fields, labels):
    """The relations of a paragraph of clause 8.2 between a flag and a field of its figure:
    each sentence that makes fields there, or not, as a flag is set or not, before its
    "otherwise". A field goes by its name, the longest first, or by its octets."""
    out = []
    bit = re.match(r'^-?\s*Bits? \d+ *[–-] *([A-Za-z0-9/-]+)', paragraph)
    for sentence in re.split(r'(?<=[.;])\s+', paragraph):
        sentence = re.split(r'\botherwise\b', sentence)[0]
        found = re.search(r'(.+?)\s*shall (not )?be present', sentence)
        if not found:
            continue
        flags = []
        if bit and re.search(r'this bit is set to "1"', sentence):
            flags.append((bit.group(1), 'set'))
        for flag, negation in re.findall(r'the ([A-Za-z0-9/-]+) (?:bit|flag)(?: in octet \d+)? is (not )?set', sentence):
            flags.append((flag, 'unset' if negation else 'set'))
        for flag in re.findall(r'\bIf ([A-Z][A-Za-z0-9/-]+) is set to "1"', sentence):
            flags.append((flag, 'set'))
        segment = found.group(1)
        absent = bool(found.group(2)) or bool(re.search(r'(?i)\b(neither|none) of\b', segment))
        named = []
        for label, name in labels.items():
            if re.search(r'(?i)octets?"?' + re.escape(label) + r'(?![a-z0-9(])', segment.replace(' ', '')) and name not in named:
                named.append(name)
        rest = segment
        # The longest name first, and names of one length in the order of the figure: a set
        # would order them by the hashes of the strings, which change from run to run.
        for name in sorted(dict.fromkeys(fields), key=len, reverse=True):
            pattern = r'(?i)(?<![A-Za-z0-9])' + re.escape(name) + r'(?![A-Za-z0-9])'
            if re.search(pattern, rest):
                named.append(name)
                rest = re.sub(pattern, ' ', rest)
        for name in named:
            out.extend([flag, state, name, 'absent' if absent else 'present'] for flag, state in flags)
    return out


# The words of a sentence of clause 8.2 that says which flags of an IE are set together,
# the first that it has in this order. A sentence of who sets a bit ("shall only be set by
# the CP function") is not of them; "sshall" is the document's.
FLAG_PHRASES = [
    ('one and only one', re.compile(r'(?i)\bone and only one\b')),
    ('only one of', re.compile(r'(?i)\bonly one of\b')),
    ('at least one', re.compile(r'(?i)\bat least one\b[^.]*?\b(?:bit|flag|of)\b')),
    ('may only be set', re.compile(r'(?i)\bmay only be set\b')),
    # Of a flag that another sets: "if the UP function is requested to" is not of them.
    ('shall be set if', re.compile(r'(?i)\bshall be set to ["“]1["”] if the [A-Za-z0-9/-]+ (?:bit|flag) is set\b')),
    ('shall not be set', re.compile(r'(?i)\bs?shall not be set\b')),
    ('either', re.compile(r'(?i)\beither\b[^.]*\b(?:bit|flag)s?\b[^.]*\bshall be set\b')),
    ('exclusive', re.compile(r'(?i)\bexclusive\b')),
    # Of the flags that a value of another field has set: "If Proxy Authen Type Value is
    # 1, then the PAN and PAR flags shall be set".
    ('flags of a value', re.compile(r'(?i)\bif [A-Za-z /-]+ is \d+, then the [A-Za-z0-9, -]+ flags? shall be set\b')),
    # Of a flag that is always set: "This bit shall be set to "1"." alone, not "to "1" if".
    ('always set', re.compile(r'(?i)\bthis (?:bit|flag) shall be set to ["“]1["”]\s*\.')),
]


def flag_sentences(paragraph):
    """The phrase of each sentence of a paragraph that says which flags are set together."""
    out = []
    for sentence in re.split(r'(?<!i\.e\.)(?<!e\.g\.)(?<=[.;:])\s+(?=[A-Z(-])', paragraph):
        phrase = next((name for name, pattern in FLAG_PHRASES if pattern.search(sentence)), None)
        if phrase:
            out.append(phrase)
    return out


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
        if not re.fullmatch(r'\d+', value) or re.match(r'(?i)spare|for future use', name):
            continue
        out.append([number, title, value, '<reserved>' if re.match(r'(?i)<?reserved', name) else name])
    return out


def read_as(number, rows):
    """The values of a table of values that a receiver reads as another: a row that says
    "If received, shall be interpreted as", a row that names a note that says so, and the
    "Other values" of a table of bits in prose."""
    notes, out = {}, []
    for row in rows:
        for cell in row:
            for label, text in re.findall(r'(NOTE(?: \d+)?):\s*(.*?)(?=NOTE(?: \d+)?:|$)', cell, flags=re.S):
                found = re.search(r'shall be interpreted as (.+?)\.', clean(text))
                if found:
                    notes[label] = found.group(1)
            for found in re.finditer(r'Other values shall be interpreted as (.+?) in this version', clean(cell)):
                out.append([number, 'other values', found.group(1)])
    for row in rows:
        if row[0].startswith('NOTE'):
            continue
        values = [cell for cell in row if re.fullmatch(r'\d+(?:, \d+)*|\d+ to \d+', cell)]
        if not values:
            continue
        cells = [clean(cell) for cell in row]
        found = [found.group(1) for cell in cells
                 for found in [re.search(r'If received, shall be interpreted as (.+?)\.?$', cell)] if found]
        named = [found.group(1) for cell in cells
                 for found in [re.search(r'\b(NOTE(?: \d+)?)\b', cell)] if found and found.group(1) in notes]
        if found:
            out.append([number, values[0], found[0]])
        elif named:
            out.append([number, values[0], notes[named[0]]])
    return out


def write(name, head, rows):
    with open(os.path.join(HERE, name), 'w', encoding='utf-8') as out:
        out.write('# ' + '\t'.join(head) + '\n')
        for row in rows:
            out.write('\t'.join(row) + '\n')
    print(f'{name}: {len(rows)} lines')


main()
