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
    row-conditions.tsv  the rows of those tables whose comment makes the IE there by what
                        the IEs beside it show: "a flag" for an IE of flags that "shall be
                        included if at least one of the flags is set", and "with X" or
                        "without X" for one that "may be present if the X IE is present",
                        or "is not included"
    row-features.tsv    the rows of those tables that require a feature of Table
                        8.2.25-1 or 8.2.58-1 ("may be present if the UP function
                        supports the NORP feature"): the function that announces the
                        features (UP or CP), the features (any one of them allows the
                        IE), and "several" when the feature is only required for more
                        than one instance of the IE
    layouts.tsv         the figures of clause 8.2: their clause, the type that they say, and
                        the names of their flags and fields, in order
    figures.tsv         the place of each flag and field of those figures: the octets of its
                        row, its lowest bit and how many bits it has
    conditions.tsv      the sentences of clause 8.2 that make a field there or not as a flag
                        is set or not: the flag, whether it is set, the field, whether it is
                        there, or "also present" where another flag has the field there;
                        and those that make it there or not as a field of bits of
                        the figure has a value: that field, "is" and the names of the
                        values, the field, whether it is there
    flag-sentences.tsv  the sentences of clause 8.2 that say which flags of an IE are set
                        together: "at least one", "one and only one", "only one of", "may
                        only be set", "shall be set to "1" if the ... flag is set", "shall
                        not be set", "either ... shall be set", "exclusive" or "shall
                        contain an IPv4 and/or IPv6 address", with the field of another
                        flag ("shall also be present"), with a value
                        ("if ... is 1, then the ... flags shall be set"), with the Cause of
                        the message ("shall be set to "1" ... if ... the Cause IE is set
                        to"), or always ("this bit shall be set to "1"."), by their clause
                        and their number in it, which flag-rules.tsv lists with the rule
                        that checks each
    range-sentences.tsv the sentences of clause 8.2 that bound the value of a field, "in
                        the range 1 to 255", "between (and including) 0 and 127", "from 0
                        up to 100", by their clause and their number in it, with the
                        bounds, which range-rules.tsv lists with the rule that checks each
    value-tables.tsv    the tables of clause 8.2 that name values, or bits as octet/bit; a
                        value that a table reserves is named <reserved>, and the spare
                        values that a note of the table has the receiver reject with
                        "Mandatory IE incorrect", "9 to 255", are named <rejected>
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
                    # The paragraphs of a cell, one to a line: a name that the
                    # document writes on two lines is one name, which clean() reads.
                    paragraphs = [text(p) for p in cell.iter(W + 'p')]
                    value = '\n'.join(p for p in paragraphs if p)
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


# A clause without a figure yet.
NO_FIGURE = {'fields': [], 'labels': {}, 'cells': [], 'narrow': [], 'numbered': {}, 'rows': [], 'table': {}}


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
    figures, conditions, flags, ranges, beside, comments = [], [], [], [], [], []
    # The figure of the clause, as relations() reads its sentences: its fields of octets,
    # by name and by their octets, its fields of bits of more than one bit, those of them
    # of rows that a letter counts, its flags by their bits, its rows, and the names of
    # the bits of the table of bits of the clause, by their octet and bit.
    shape = dict(NO_FIGURE)
    for kind, block in blocks(body):
        if kind == 'p':
            style, value = block
            if style.startswith('Heading') or re.match(r'^8\.2\.\d+ [A-Z]', value) and style == '':
                heading = value
                shape = dict(NO_FIGURE, table={})
                if re.match(r'^6(\.\d+)* ', value):
                    clause6.append(value.split(' ', 1) + [0])
            elif clause6 and re.match(r'^6(\.\d+)* ', heading):
                clause6[-1][2] += len(requirements(value))
            elif re.match(r'^8\.2\.\d+ ', heading):
                conditions.extend([heading.split(' ', 1)[0]] + relation for relation in relations(value, shape))
                clause = heading.split(' ', 1)[0]
                for phrase in flag_sentences(value):
                    flags.append([clause, str(sum(row[0] == clause for row in flags) + 1), phrase])
                for bounds in range_sentences(value):
                    ranges.append([clause, str(sum(row[0] == clause for row in ranges) + 1), bounds])
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
                    beside.extend([number, without_notes(row[0]), condition] for condition in row_conditions(row[2]))
                    comments.append((number, without_notes(row[0]), row[2]))
            # An IE beside a row is a row of its table.
            named = {row[2] for row in tables if row[0] == 'row' and row[1] == number}
            beside = [row for row in beside if row[0] != number or row[2] == 'a flag' or row[2].split(' ', 1)[1] in named]
        elif title and re.match(r'Table 8\.2\.\d+[.-]\d+', title):
            number = re.match(r'Table (8\.2\.\d+[.-]\d+)', title).group(1)
            named = value_rows(number, title.split(':', 1)[1].strip(), rows)
            values.extend(named)
            if re.match(r'^8\.2\.\d+ ', heading):
                shape['table'].update({row[2]: row[3] for row in named if '/' in row[2]})
            read.extend(read_as(number, rows))
        elif re.match(r'^8\.2\.\d+ ', heading):
            figure = members(rows, spans)
            if figure:
                layouts.append([heading.split(' ', 1)[0]] + figure)
                found = places(block, widths)
                figures.extend([heading.split(' ', 1)[0]] + place for place in found)
                shape.update(
                    fields=[name for _, name, _, bits in found if bits == '8'],
                    labels={re.sub(r'\s+', '', octets): name for octets, name, _, bits in found if bits == '8'},
                    cells=[name for _, name, _, bits in found if 1 < int(bits) < 8],
                    narrow=[name for octets, name, _, bits in found if 1 < int(bits) < 8 and offsets(octets)],
                    numbered={bit: name for octets, name, bit, bits in found if bits == '1' and octets == found[0][0]},
                    rows=[(octets, name) for octets, name, _, bits in found],
                )
    write('message-types.tsv', ['value', 'name', 'interfaces'], message_types)
    write('ie-types.tsv', ['type', 'name', 'reference', 'length'], ie_types)
    write('tables.tsv', ['table|row|same', 'table', 'name, or the name of the row', 'heading, or presence', 'IE type, or interfaces', 'IE type', 'once, several, or how many'], tables)
    write('row-conditions.tsv', ['table', 'row', 'there'], beside)
    write('row-features.tsv', ['table', 'row', 'function', 'features', 'one or several'], row_features(comments, values))
    write('layouts.tsv', ['clause', 'type in the figure', 'fields'], layouts)
    write('figures.tsv', ['clause', 'octets', 'name', 'lowest bit', 'bits'], figures)
    write('conditions.tsv', ['clause', 'flag', 'set', 'field', 'there'], conditions)
    write('flag-sentences.tsv', ['clause', 'n', 'phrase'], flags)
    write('range-sentences.tsv', ['clause', 'n', 'bounds'], ranges)
    write('value-tables.tsv', ['table', 'title', 'value', 'name'], values)
    write('read-as.tsv', ['table', 'values', 'read as'], read)
    write('clause-6.tsv', ['clause', 'title', 'requirements'], [[c, t, str(n)] for c, t, n in clause6])


# An IE of flags that is there with a flag set: "This IE shall be included if at least one
# of the flags is set to "1"", "if any of the following flag is set", "if any of flag in
# this IE is set".
A_FLAG = re.compile(r'(?i)\b(?:included|present) if (?:at least one|any) (?:of )?(?:the )?(?:following )?flags?\b(?! in the [A-Z])')
# An IE that may be there with another of its table, or without it: "This IE may be present
# if the Monitoring Time IE is present and ...", "may be included if the Time Domain Number
# IE is not included", "may be present when the Old CP F-SEID is present"; not one of two
# conditions ("if the Query URR IE is present or the QAURR flag is set").
BESIDE = re.compile(r'\b(?:if|when) (?:the )?([A-Z][A-Za-z0-9 /-]*?)(?: IE)? is (not )?(?:present|included)\b(?! or\b)')


def row_conditions(comment):
    """What the comment of a row of a table of clause 7 says of the IE by the IEs beside
    it: "a flag", "with X", "without X"."""
    out = []
    for sentence in re.split(r'(?<=[.;])\s+', clean(comment)):
        if A_FLAG.search(sentence):
            out.append('a flag')
        may = re.search(r'\bmay be (?:present|included)\b', sentence)
        if may:
            for name, negation in BESIDE.findall(sentence[may.end():]):
                out.append(('without ' if negation else 'with ') + name)
    return out


def row_features(comments, values):
    """The rows whose comment requires a feature for the IE: "This IE may be present if
    the UP function supports the NORP feature", "shall be present if ... and if the UPF
    indicated support of the DRQOS feature". A comment may also require the feature only
    for more than one instance: "several IEs with the same IE type may be present ..., if
    the UPF indicated support of the IP6PL feature". A feature is a name of Table 8.2.25-1
    or 8.2.58-1 that the sentence calls a feature. SSET and MPAS are in both tables: the
    function is the CP function when the sentence names the SMF or the CP function."""
    names = {'UP': {}, 'CP': {}}
    for table, _, place, name in values:
        if table in ('8.2.25-1', '8.2.58-1') and '/' in place:
            names['UP' if table == '8.2.25-1' else 'CP'][name] = place
    name = '|'.join(sorted(map(re.escape, set(names['UP']) | set(names['CP'])), key=len, reverse=True))
    called = re.compile(r'(?<![A-Za-z0-9-])((?:%s)(?:(?: and/or | or | and )(?:%s))*) feature\b|\bfeature ((?:%s))(?![A-Za-z0-9-])' % (name, name, name))
    out = []
    for table, row, comment in comments:
        for sentence in re.split(r'(?<=[.;])\s+', clean(comment)):
            one = re.search(r'\b(?:may be (?:present|included),? (?:if|when)|shall be (?:present|included) (?:if|when))\b(.*)', sentence)
            several = re.search(r'(?i)\bseveral IEs with the same IE type may be present\b(.*)', sentence)
            there = several or one
            if not there or not re.search(r'(?i)\bsupport', there.group(1)):
                continue
            words = there.group(1)
            found = []
            for listed, after in called.findall(words):
                found.extend(re.split(r' and/or | or | and ', listed) if listed else [after])
            both = [feature for feature in found if feature in names['UP'] and feature in names['CP']]
            function = 'CP' if (both and re.search(r'\bSMF\b|\bCP [Ff]unction', words)) or (found and found[0] not in names['UP']) else 'UP'
            found = [feature for feature in dict.fromkeys(found) if feature in names[function]]
            if found:
                out.append([table, row, function, ' | '.join(found), 'several' if several else 'one'])
    return out


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


def offsets(label):
    """The octets of a row of a figure that its label counts from a letter: "m" is (m, 0,
    0), "(m+1) to (m+2)" (m, 1, 2), "a to (a+1)" (a, 0, 1); None for another label."""
    label = re.sub(r'[\s"\']', '', label)
    found = re.fullmatch(r'\(?([a-z])(?:\+(\d+))?\)?(?:to\(?\1(?:\+(\d+))?\)?)?', label)
    if not found:
        return None
    low = int(found.group(2) or 0)
    return found.group(1), low, int(found.group(3) or low)


def relations(paragraph, figure):
    """The relations of a paragraph of clause 8.2 between a flag and a field of its figure:
    each sentence that makes fields there, or not, as a flag is set or not, before its
    "otherwise". A flag goes by its name, as the bit of the paragraph ("Bit 1 – FD"), "the
    CH bit", "If PPI is set to", "bit 1 (ULPR)", by its number ("either bit 1 or bit 2") or
    by its place in the table of bits of the clause ("any of the bits 5/1 and 5/2"); it is
    set, or not ("is not set", "is set to "0""). A field goes by its name, the longest
    first, by the first of a numbered series without its number, or by its octets, of one
    row or of several ("octets m to (m+2)"); a name that the figure does not have is
    written as the sentence has it after "then the", which errata.tsv gives its field.
    And those between the value of a field of bits and a field (value_relations)."""
    out = []
    bit = re.match(r'^-?\s*Bits? \d+ *[–-] *([A-Za-z0-9/-]+)', paragraph)
    fields = figure['fields'] + figure['narrow']
    # A sentence goes on after "i.e." where it then says the bits of its condition.
    for sentence in re.split(r'(?<=[.;])\s+(?!if in Octet\b)', paragraph):
        out.extend(value_relations(sentence, figure['fields'], figure['cells']))
        sentence = re.split(r'\botherwise\b', sentence)[0]
        found = re.search(r'(.+?)\s*shall (not )?(also )?be presen[td]', sentence)
        if not found:
            continue
        flags = []
        if bit and re.search(r'this bit is set to "1"', sentence):
            flags.append((bit.group(1), 'set'))
        for flag, negation, value in re.findall(r'the ([A-Za-z0-9/-]+) (?:bit|flag)(?: in octet \d+)? is (not )?set(?: to "([01])")?', sentence):
            flags.append((flag, 'unset' if negation or value == '0' else 'set'))
        for flag, value in re.findall(r'\bIf ([A-Z][A-Za-z0-9/-]+) is set to "([01])"', sentence):
            flags.append((flag, 'unset' if value == '0' else 'set'))
        for flag in re.findall(r'\bbit \d \(([A-Za-z0-9/-]+)\) is set to "1"', sentence):
            flags.append((flag, 'set'))
        for numbers in re.findall(r'\beither bit (\d) or bit (\d) is set\b', sentence):
            flags.extend((figure['numbered'][number], 'set') for number in numbers if number in figure['numbered'])
        for places in re.findall(r'\bany of the bits ((?:\d/\d(?:, | and )?)+) are set\b', sentence):
            flags.extend((figure['table'][place], 'set') for place in re.findall(r'\d/\d', places) if place in figure['table'])
        segment = found.group(1)
        absent = bool(found.group(2)) or bool(re.search(r'(?i)\b(neither|none) of\b', segment))
        named = []
        for label, name in figure['labels'].items():
            if re.search(r'(?i)octets?"?' + re.escape(label) + r'(?![a-z0-9(])', segment.replace(' ', '')) and name not in named:
                named.append(name)
        # The rows of the octets that the sentence names from a letter: "octets m to
        # (m+2)", "octets 'a' to (a+1)", "octet "m"", "octets "q" to "q+1"".
        for letter, last in re.findall(r'\boctets? ["\']?([a-z])["\']?(?: to ["\']?\(?\1\+(\d+)\)?["\']?)?(?![A-Za-z0-9])', segment):
            for label, name in figure['rows']:
                place = offsets(label)
                if place and place[0] == letter and place[2] <= int(last or 0) and name not in named:
                    named.append(name)
        rest = segment
        # The longest name first, and names of one length in the order of the figure: a set
        # would order them by the hashes of the strings, which change from run to run.
        for name in sorted(dict.fromkeys(fields), key=len, reverse=True):
            # The first of a numbered series goes without its number too.
            series = re.sub(r' (?:1|instances)$', '', name)
            for written in dict.fromkeys([name, series]):
                pattern = r'(?i)(?<![A-Za-z0-9])' + re.escape(written) + r'(?![A-Za-z0-9])'
                if re.search(pattern, rest):
                    if name not in named:
                        named.append(name)
                    rest = re.sub(pattern, ' ', rest)
                    break
        # A name that the figure does not have, as the sentence writes it.
        written = re.search(r'\bthen the (.+?)(?: fields?)?$', segment.strip())
        if flags and not named and written:
            named.append(written.group(1))
        # A field that is "also" there with a flag is one that another flag has there: the
        # two flags are set together, which a sentence of flags says (FLAG_PHRASES).
        there = 'absent' if absent else 'also present' if found.group(3) else 'present'
        for name in named:
            out.extend([flag, state, name, there] for flag, state in dict.fromkeys(flags))
    return out


# A value of a field of bits that a sentence of clause 8.2 names: "is set to Port", "is set
# to "IPv4 address and Port", "IPv6 address and Port", or ...", "indicates the event report
# is delay tolerant".
VALUES = r'(?:is set to|indicates (?:that )?(?:the [a-z ]+? is )?)\s*("[^"]+"(?:,? (?:or |and )?"[^"]+")*|[A-Za-z][A-Za-z0-9 -]*?)(?=[,.]|$)'


def value_relations(sentence, fields, cells):
    """The relations of a sentence of clause 8.2 between the value of a field of bits of
    more than one bit and the fields that it makes there, or not: "If the Redirect Address
    Type is set to Port, the Redirect Address Server Address shall not be present". The
    fields are those named where the sentence says they are or are not, before "shall be
    present" or "shall be included", after "shall include": by their names in the figure,
    the longest first, and any other name of capitals as the sentence writes it, which
    errata.tsv maps to a field of the crate."""
    presence = re.search(r'\bshall (not )?(?:also )?be (?:present|included)\b|\bshall include\b', sentence)
    if not presence:
        return []
    for cell in sorted(cells, key=len, reverse=True):
        name = re.escape(re.sub(r'\s+value$', '', cell))
        condition = re.search(r'(?i)\b(?:if|when) (?:the )?' + name + r'(?: value)? ' + VALUES, sentence)
        if condition:
            break
    else:
        return []
    values = re.findall(r'"([^"]+)"', condition.group(1)) or [condition.group(1)]
    if presence.group(0) == 'shall include':
        named = sentence[presence.end():]
    else:
        named = sentence[:presence.start()]
    named = named.replace(condition.group(0), ' ')
    found = []
    for field in sorted(dict.fromkeys(fields), key=len, reverse=True):
        pattern = r'(?i)(?<![A-Za-z0-9])' + re.escape(field) + r'(?![A-Za-z0-9])'
        if re.search(pattern, named):
            found.append(field)
            named = re.sub(pattern, ' ', named)
    found.extend(re.findall(r'\b[A-Z][A-Za-z0-9/-]*(?: [A-Z][A-Za-z0-9/-]*)+', named))
    there = 'absent' if presence.group(1) else 'present'
    return [[cell, 'is ' + ' | '.join(values), field, there] for field in found]


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
    # Of an IE of addresses that has one: "The CP IP Address IE shall contain an IPv4
    # and/or IPv6 address", one of the flags V4 and V6.
    ('an address', re.compile(r'(?i)\bshall contain an IPv4 and/or IPv6 address\b')),
    # Of a flag whose field is of the field of another flag: "if this bit is set to "1",
    # the Length of Domain Name and the Domain Name fields shall also be present".
    ('also present', re.compile(r'(?i)\bif this bit is set to ["“]1["”],[^.;]*\bshall also be present\b')),
    # Of a flag that is always set: "This bit shall be set to "1"." alone, not "to "1" if".
    ('always set', re.compile(r'(?i)\bthis (?:bit|flag) shall be set to ["“]1["”]\s*\.')),
    # Of a flag that the Cause of the message has set: "This flag shall be set to "1" by
    # the UP function, if ... the Cause IE is set to a rejection cause value".
    ('with the Cause', re.compile(r'(?i)\bshall be set to ["“]1["”][^.]*\bif\b[^.]*\bthe Cause IE is set to\b')),
]


def flag_sentences(paragraph):
    """The phrase of each sentence of a paragraph that says which flags are set together."""
    out = []
    for sentence in re.split(r'(?<!i\.e\.)(?<!e\.g\.)(?<=[.;:])\s+(?=[A-Z(-])', paragraph):
        phrase = next((name for name, pattern in FLAG_PHRASES if pattern.search(sentence)), None)
        if phrase:
            out.append(phrase)
    return out


# The bounds of a value that a sentence of clause 8.2 says: "in the range 1 to 255", "in the
# (decimal) values range 0 to 10000", "between (and including) 0 and 127", "the range of
# the Packet Count value is from 0 to 255", "from 0 up to 100".
RANGE = re.compile(r'(?i)\b(?:range|between)\b[^.;]{0,40}?\b(\d+) (?:to|and) (\d+)\b|\bfrom (\d+) up to (\d+)\b')


def range_sentences(paragraph):
    """The bounds of each sentence of a paragraph that bounds the value of a field."""
    out = []
    for sentence in re.split(r'(?<!i\.e\.)(?<!e\.g\.)(?<=[.;:])\s+(?=[A-Z(-])', paragraph):
        for found in RANGE.finditer(sentence):
            low, high = [group for group in found.groups() if group is not None]
            out.append(f'{low} to {high}')
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
        for bits, words in re.findall(r'([01] [01] [01]) ([^\n]+)', rows[0][0]):
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
    # The notes of the table that have the receiver reject an unknown value.
    rejecting = set()
    for row in rows:
        for cell in row:
            for label, words in re.findall(r'(NOTE(?: \d+)?):\s*(.*?)(?=NOTE(?: \d+)?:|$)', cell, flags=re.S):
                if re.search(r'unknown value, it shall reject the request message with the cause set to "Mandatory IE incorrect"', clean(words)):
                    rejecting.add(label)
    out = []
    for row in rows[1:]:
        if len(row) <= max(at, name_at) or row[0].startswith('NOTE'):
            continue
        value, name = row[at], without_notes(row[name_at])
        name = clean(re.sub(r'\s+– see .*$|\s*\(see clause .*$', '', name)).rstrip('.')
        if re.match(r'(?i)spare', name) and re.fullmatch(r'\d+ to \d+', value) and rejecting & set(re.findall(r'NOTE(?: \d+)?', row[name_at])):
            out.append([number, title, value, '<rejected>'])
            continue
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
