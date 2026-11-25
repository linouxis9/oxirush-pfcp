#!/usr/bin/env python3
"""Compare Wireshark's reading of PFCP messages with this crate's, field by field.

    python3 -I tests/wireshark/compare.py --corpus corpus.tsv --crate crate.jsonl \\
        --mapping tests/wireshark/mapping.tsv --known tests/wireshark/known.tsv --output OUT

--corpus has a message a line, its name and its octets in hexadecimal (tests/go-pfcp/corpus.py
writes it); --crate what the crate read of each (the test `wireshark`). Each message is sent
to tshark as a UDP datagram to port 8805, which it dissects as PFCP, and tshark writes PDML.
Each message is then one of:

  agree          both read it, with the same header and the same IEs at the same offsets
                 at every level, and every field that the mapping compares is the same;
  differs        both read it, and something of that differs;
  both-refuse    Wireshark finds it malformed or reports an error, and the crate does not
                 decode it, or check() tells that one of its IEs or values is incorrect;
  ws-malformed   Wireshark finds it malformed or reports an error, and the crate reads it
                 and finds nothing incorrect;
  crate-refuses  Wireshark reads it without an error, and the crate does not decode it.

A difference is explained by a row of --known, or fails the run. OUT has report.json (each
message that is not `agree`, with its differences), summary.txt and coverage.tsv (each field
that Wireshark showed in an IE, and how many times it was compared or why not). The run fails
too where tshark is not the pinned one, without --any-tshark, and where nothing is compared.
"""

import argparse
import collections
import datetime
import ipaddress
import json
import re
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

PINNED = "TShark (Wireshark) 4.6.4"
# Ethernet, IPv4 and UDP before the PFCP message of each datagram
BEFORE = 14 + 20 + 8
# What check() tells of an IE that does not frame or of a value that does not decode, or
# breaks a rule of its clause
INCORRECT = re.compile(r": (InvalidLength|MandatoryIncorrect|ConditionalIncorrect|FixedLength|ReservedValue|Rule|VendorId|UnknownType)\b")
# The fields of an IE that are its frame, or spare, and compared as such or not at all
FRAME = {"pfcp.ie_type", "pfcp.enterprise_ie", "pfcp.ie_len", "pfcp.enterprise_id"}


def pcap(messages, path):
    """A capture of one UDP datagram to port 8805 a message."""
    with open(path, "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for number, (_, octets) in enumerate(messages):
            udp = struct.pack(">HHHH", 8805, 8805, 8 + len(octets), 0) + octets
            ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), number & 0xFFFF, 0, 64, 17, 0,
                             bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + udp
            frame = bytes(range(12)) + b"\x08\x00" + ip
            out.write(struct.pack("<IIII", number, 0, len(frame), len(frame)) + frame)


class Field:
    """A field of PDML."""

    __slots__ = ("name", "show", "showname", "value", "pos", "size")

    def __init__(self, element):
        self.name = element.get("name", "")
        self.show = element.get("show", "")
        self.showname = element.get("showname", "")
        self.value = element.get("value", "")
        self.pos = int(element.get("pos", "0")) - BEFORE
        self.size = int(element.get("size", "0"))

    def label(self):
        """What a coded value means, from `Name: meaning (code)`."""
        text = self.showname.split(" = ", 1)[-1] if " = " in self.showname else self.showname
        text = text.split(": ", 1)[1] if ": " in text else text
        return re.sub(r"\s*\((?:0x)?[0-9a-fA-F]+\)$", "", text).strip()


class Ie:
    """An IE as Wireshark dissects it: its offset, type, Length, fields and IEs."""

    def __init__(self, element):
        self.offset = int(element.get("pos", "0")) - BEFORE
        self.type = None
        self.length = None
        self.enterprise_id = None
        self.fields = []
        self.ies = []
        self.collect(element)

    def collect(self, element):
        for child in element:
            if child.tag != "field":
                continue
            if is_ie(child):
                self.ies.append(Ie(child))
                continue
            field = Field(child)
            if field.name in ("pfcp.ie_type", "pfcp.enterprise_ie") and self.type is None:
                self.type = int(field.show)
            elif field.name == "pfcp.enterprise_id" and self.enterprise_id is None:
                self.enterprise_id = int(field.show)
            elif field.name == "pfcp.ie_len" and self.length is None:
                self.length = int(field.show)
            elif field.name and not field.name.startswith("_ws."):
                self.fields.append(field)
            self.collect(child)


def is_ie(element):
    """Whether a field of PDML is an IE: one without a name whose own fields begin with its
    type, of 3GPP or of a vendor."""
    return element.get("name", "") == "" and any(
        child.get("name") in ("pfcp.ie_type", "pfcp.enterprise_ie") for child in element if child.tag == "field")


class Dissection:
    """What Wireshark reads of one datagram: the header and IEs of its first PFCP message,
    and the errors that it reports."""

    def __init__(self, packet):
        self.header = {}
        self.ies = []
        self.errors = []
        self.pfcp = False
        for proto in packet:
            name = proto.get("name")
            if name == "pfcp" and not self.pfcp:
                self.pfcp = True
                for child in proto:
                    if child.tag != "field":
                        continue
                    if is_ie(child):
                        self.ies.append(Ie(child))
                    elif child.get("name", "").startswith("pfcp."):
                        self.header.setdefault(child.get("name"), child.get("show", ""))
        for element in packet.iter("field"):
            if element.get("name") == "_ws.expert":
                severity = next((f.get("showname", "") for f in element if f.get("name") == "_ws.expert.severity"), "")
                if "Error" in severity:
                    text = element.get("showname", "").replace("Expert Info ", "")
                    self.errors.append((self.at(int(element.get("pos", "0")) - BEFORE), text))

    def at(self, offset):
        """The IEs from the outermost to the innermost that hold `offset`, or that lead to the
        last IE that Wireshark dissected, where it stopped: an exception is reported after the
        message."""
        chain, ies = [], self.ies
        while ies:
            holder = next((ie for ie in ies if ie.length is not None and ie.offset <= offset < ie.offset + 4 + ie.length), None)
            if holder is None:
                break
            chain.append(holder)
            ies = holder.ies
        if not chain:
            ies = self.ies
            while ies:
                chain.append(ies[-1])
                ies = ies[-1].ies
        return chain


def dissect(pcap_path, keep):
    """The dissection of each datagram, in order, through the PDML in `keep`."""
    with open(keep, "wb") as out:
        subprocess.run(["tshark", "-r", str(pcap_path), "-T", "pdml", "-o", "pfcp.port_pfcp:8805"],
                       stdout=out, stderr=subprocess.DEVNULL, check=True)
    found = []
    for _, element in ET.iterparse(keep, events=("end",)):
        if element.tag == "packet":
            found.append(Dissection(element))
            element.clear()
    return found


def number(text):
    text = text.strip()
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def same(kind, show, field, member, names):
    """Whether Wireshark's field and the crate's member read the same, by the comparison of
    a mapping row; None where the comparison does not apply. Octets that the crate writes in
    hexadecimal, where it does not read them as text or as a number, are compared with the
    octets of Wireshark's field."""
    if kind == "bool":
        theirs = field.value not in ("", "0") if field.value else show == "True"
        return theirs == bool(member)
    if member is None:
        return None
    octets = field.value.lower()
    if isinstance(member, str) and re.fullmatch(r"(?:[0-9a-f]{2})+", member) and member == octets:
        return True
    if kind == "int":
        if isinstance(member, str) and re.fullmatch(r"[0-9a-f]+", member):
            return number(show) == int(member, 16)
        return isinstance(member, (int, bool)) and number(show) == int(member)
    if kind == "int31":
        # A rule ID whose bit 8 of octet 5 says that the UP function predefined it: Wireshark
        # shows the 31 bits below it, the crate the Unsigned32 of the clause
        return isinstance(member, int) and number(show) == member & 0x7FFFFFFF
    if kind == "bit32":
        # The bit of a predefined rule, bit 8 of octet 5 of its ID
        theirs = field.value not in ("", "0") if field.value else show == "True"
        return isinstance(member, int) and theirs == bool(member >> 31)
    if kind == "ip":
        return isinstance(member, str) and ipaddress.ip_address(show) == ipaddress.ip_address(member)
    if kind == "text":
        return isinstance(member, str) and (show == member or member.encode().hex() == octets)
    if kind == "name":
        # A value without a name in the crate's table is its number
        if isinstance(member, int):
            return number(show) == member
        listed = names.get((field.name, show))
        normal = lambda text: re.sub(r"[^0-9a-z]+", " ", str(text).lower()).strip()
        theirs, ours = normal(listed if listed is not None else field.label()), normal(member)
        # A name that one writes with an explanation after it
        return theirs == ours or (" " in theirs and ours.startswith(theirs + " "))
    if kind == "hex":
        return isinstance(member, str) and octets == member.lower()
    if kind == "time":
        # A time of PFCP is the seconds of RFC 5905 from 1900, which Wireshark shows in UTC
        when = datetime.datetime.fromisoformat(show.rstrip("Z").split(".")[0]).replace(tzinfo=datetime.timezone.utc)
        return isinstance(member, int) and (int(when.timestamp()) + 2208988800) % 2**32 == member
    raise ValueError(f"no comparison {kind}")


def member_of(tree, member):
    """The member of a value's tree (`.` the tree itself, as a scalar). The tree of a scalar
    value with unknown octets after it, or spare bits, is an object of the value and of
    those; a coded value with spare bits is an object of its `value` and its `Spare`."""
    if member == ".":
        value = tree
        if isinstance(tree, dict):
            members = [name for name in tree if name not in ("unknown octets", "Spare", "length")]
            value = tree[members[0]] if len(members) == 1 else None
    else:
        value = tree.get(member) if isinstance(tree, dict) else None
    if isinstance(value, dict) and "value" in value:
        value = value["value"]
    return value


class Mapping:
    def __init__(self, path):
        self.fields = {}
        self.none = {}
        self.names = {}
        for line in open(path, encoding="utf-8"):
            if line.startswith("#") or not line.strip():
                continue
            row = line.rstrip("\n").split("\t")
            if row[0] == "field":
                _, ie_type, field, member, kind = row[:5]
                self.fields[(int(ie_type), field)] = (member, kind)
            elif row[0] == "none":
                _, ie_type, field, why = row[:4]
                self.none[(ie_type, field)] = why
            elif row[0] == "value":
                _, field, code, name = row[:4]
                self.names[(field, code)] = name
            else:
                raise ValueError(f"a row of mapping.tsv: {line}")

    def nothing(self, ie_type, field):
        return self.none.get((str(ie_type), field)) or self.none.get(("*", field)) or (
            "spare" if ".spare" in field or field.startswith("pfcp.spare") else None)


def compare_ies(level, theirs, ours, mapping, coverage, differences):
    """Compare the IEs of a scope, by their offsets."""
    by_offset = {ie["offset"]: ie for ie in ours if "type" in ie}
    faults = {ie["offset"]: ie["fault"] for ie in ours if "fault" in ie}
    seen = set()
    for ie in theirs:
        mine = by_offset.get(ie.offset)
        if mine is None and ie.offset in faults:
            differences.append(("ie", f"{level} IE {ie.type} at {ie.offset}: Wireshark dissects it, the crate stops: {faults[ie.offset]}"))
            break
        if mine is None:
            differences.append(("ie", f"{level} IE {ie.type} at {ie.offset}: only Wireshark"))
            continue
        seen.add(ie.offset)
        header = (ie.type, ie.length, ie.enterprise_id)
        if (mine["type"], mine["length"], mine.get("enterprise_id")) != header:
            differences.append(("ie", f"{level} IE at {ie.offset}: Wireshark {header}, crate {(mine['type'], mine['length'], mine.get('enterprise_id'))}"))
            continue
        if mine.get("grouped"):
            compare_ies(f"{level}/{ie.type}", ie.ies, mine.get("ies", []), mapping, coverage, differences)
            continue
        tree = mine.get("tree")
        named = collections.Counter()
        for field in ie.fields:
            key = (ie.type, field.name)
            # A field that Wireshark shows several times in an IE, an entry of a list after
            # the field of the same name: the first is the one that a member names
            named[field.name] += 1
            if named[field.name] > 1:
                coverage[key]["shown again in the IE"] += 1
                continue
            if key in mapping.fields:
                path, kind = mapping.fields[key]
                if tree is None:
                    coverage[key]["crate keeps the IE as octets"] += 1
                    continue
                try:
                    verdict = same(kind, field.show, field, member_of(tree, path), mapping.names)
                except ValueError:
                    coverage[key]["Wireshark shows no value of the comparison"] += 1
                    continue
                if verdict is None:
                    coverage[key]["the crate's value has no such member"] += 1
                elif verdict:
                    coverage[key]["same"] += 1
                else:
                    coverage[key]["differs"] += 1
                    shown = json.dumps(member_of(tree, path))
                    differences.append(("field", f"{ie.type} {field.name}: Wireshark {field.show!r} ({field.label()}), crate {shown}"))
            elif field.name not in FRAME:
                coverage[key][mapping.nothing(ie.type, field.name) or "unlisted"] += 1
    for ie in ours:
        if "type" in ie and ie["offset"] not in seen and not any(t.offset == ie["offset"] for t in theirs):
            differences.append(("ie", f"{level} IE {ie['type']} at {ie['offset']}: only the crate"))


def crate_ie(ies, offset):
    """The IE of the crate's reading at `offset`, at any level."""
    for ie in ies:
        if ie.get("offset") == offset and "type" in ie:
            return ie
        found = crate_ie(ie.get("ies", []), offset)
        if found is not None:
            return found
    return None


def crate_fault(ies, offset):
    """Whether the crate's reading stops at `offset`, at any level, where an IE does not frame."""
    return any((ie.get("offset") == offset and "fault" in ie) or crate_fault(ie.get("ies", []), offset) for ie in ies)


def read_where(dissection, crate):
    """Of each error of Wireshark, the IEs where it is, by their types, and what the crate
    reads there: an IE that its receiver discards (§7.6.9, §7.6.10), as check() tells of its
    type, and whose value the crate does not read, in itself or in an IE that holds it; one
    where the crate stops, an IE that does not frame; or its reading. Wireshark reports an
    exception after the message, and its subtree ends with the last IE that it dissected:
    the exception is in that IE or in the next, and the crate's reading of either that finds
    something is the one given."""
    ies = crate.get("ies", [])
    told = " ".join(crate.get("told", []))
    discarded = {int(found) for found in re.findall(
        r"(?:Unexpected|Repeated|Excluded|NotOnInterface|UnknownType) \{ ie_type: (\d+)", told)}
    order = ["the crate discards it", "the crate stops there", "the crate keeps it as octets",
             "the crate reads its IEs", "the crate decodes it", "the crate has no IE there"]

    def reading(types, offset, outer):
        mine = crate_ie(ies, offset) if offset is not None else None
        if any(ie_type in discarded for ie_type in types):
            return "the crate discards it"
        if any(crate_fault(ies, at) for at in outer + [offset] if at is not None):
            return "the crate stops there"
        if mine is None:
            return "the crate has no IE there"
        if mine.get("grouped"):
            return "the crate reads its IEs"
        if mine.get("tree") is None:
            return "the crate keeps it as octets"
        return "the crate decodes it"

    found = []
    for chain, text in dissection.errors:
        if not chain:
            # An error of a message of no IE, in its header or of its type
            unknown = "UnknownMessage" in told or "MessageNotOnInterface" in told
            what = "the crate reads a message of a type that no table has" if unknown else "the crate reads a message of no IE"
            found.append(f"IE none: {text} ({what})")
            continue
        types = [ie.type for ie in chain]
        candidates = [(types, chain[-1].offset if chain else None)]
        if chain and "Exception occurred" in text and chain[-1].length is not None:
            after = chain[-1].offset + 4 + chain[-1].length
            following = crate_ie(ies, after)
            next_types = types[:-1] + [following["type"] if following else "next"]
            candidates.append((next_types, after))
        outer = [ie.offset for ie in chain[:-1]]
        best = min(((reading(types, offset, outer), types) for types, offset in candidates), key=lambda pair: order.index(pair[0]))
        found.append(f"IE {'/'.join(str(ie_type) for ie_type in best[1]) or 'none'}: {text} ({best[0]})")
    return found


def classify(dissection, crate, mapping, coverage):
    differences = []
    error = "; ".join(f"IE {'/'.join(str(ie.type) for ie in chain) or 'none'}: {text}" for chain, text in dissection.errors)
    if not dissection.pfcp:
        return ("both-refuse", []) if not crate["decodes"] else ("ws-malformed", [("ws-malformed", "no PFCP")])
    # The crate refuses a message that it does not decode; one of which check() tells that
    # an IE or a value is incorrect, it reads, and finds at fault as Wireshark may
    incorrect = [told for told in crate.get("told", []) if INCORRECT.search(told)]
    if (not crate["decodes"] or incorrect) and dissection.errors:
        return "both-refuse", []
    if not crate["decodes"]:
        return "crate-refuses", [("crate-refuses", crate.get("error") or "")]
    if dissection.errors:
        return "ws-malformed", [("ws-malformed", where) for where in read_where(dissection, crate)]
    header = dissection.header
    for field, ours in (("pfcp.msg_type", crate.get("message_type")), ("pfcp.seqno", crate.get("sequence"))):
        if field in header and number(header[field]) != ours:
            differences.append(("header", f"{field}: Wireshark {header[field]}, crate {ours}"))
    seid = crate.get("seid")
    if ("pfcp.seid" in header) != (seid is not None) or (seid is not None and number(header["pfcp.seid"]) != seid):
        differences.append(("header", f"pfcp.seid: Wireshark {header.get('pfcp.seid')}, crate {seid}"))
    compare_ies("message", dissection.ies, crate.get("ies", []), mapping, coverage, differences)
    return ("differs" if differences else "agree"), differences


class Known:
    def __init__(self, path):
        self.rows = []
        for line in open(path, encoding="utf-8"):
            if line.startswith("#") or not line.strip():
                continue
            what, where, verdict, reference = line.rstrip("\n").split("\t")[:4]
            self.rows.append((what, re.compile(where), verdict, reference))

    def explain(self, what, where):
        for row in self.rows:
            if row[0] in ("*", what) and row[1].search(where):
                return row
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--crate", required=True)
    parser.add_argument("--mapping", required=True)
    parser.add_argument("--known", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--any-tshark", action="store_true")
    arguments = parser.parse_args()
    version = subprocess.run(["tshark", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    if not version.startswith(PINNED) and not arguments.any_tshark:
        sys.exit(f"{version}: the known differences were triaged with {PINNED}")
    output = Path(arguments.output)
    output.mkdir(parents=True, exist_ok=True)
    messages = []
    for line in open(arguments.corpus, encoding="utf-8"):
        name, octets = line.rstrip("\n").split("\t")
        messages.append((name, bytes.fromhex(octets)))
    crate = [json.loads(line) for line in open(arguments.crate, encoding="utf-8")]
    if [entry["name"] for entry in crate] != [name for name, _ in messages]:
        sys.exit("the readings of the crate are not those of the corpus")
    with tempfile.TemporaryDirectory() as scratch:
        pcap(messages, Path(scratch) / "messages.pcap")
        dissections = dissect(Path(scratch) / "messages.pcap", Path(scratch) / "messages.pdml")
    if len(dissections) != len(messages):
        sys.exit(f"tshark dissected {len(dissections)} of {len(messages)} messages")
    mapping, known = Mapping(arguments.mapping), Known(arguments.known)
    coverage = collections.defaultdict(collections.Counter)
    classes = collections.Counter()
    explained = collections.Counter()
    unknown = collections.OrderedDict()
    report = []
    for (name, octets), dissection, reading in zip(messages, dissections, crate):
        kind, differences = classify(dissection, reading, mapping, coverage)
        classes[kind] += 1
        entries = []
        for what, where in differences:
            row = known.explain(what, where)
            entries.append({"what": what, "where": where, "verdict": row[2] if row else None,
                            "reference": row[3] if row else None})
            if row:
                explained[(row[2], row[3])] += 1
            else:
                unknown.setdefault((what, where), name)
        if kind != "agree":
            report.append({"name": name, "octets": octets.hex(), "class": kind, "differences": entries})
    (output / "report.json").write_text(json.dumps(report, indent=1))
    with open(output / "coverage.tsv", "w", encoding="utf-8") as out:
        out.write("ie type\tfield\thow\ttimes\n")
        for (ie_type, field), how in sorted(coverage.items()):
            for what, times in sorted(how.items()):
                out.write(f"{ie_type}\t{field}\t{what}\t{times}\n")
    lines = [version, f"{len(messages)} messages"]
    lines += [f"{classes[kind]:>7}  {kind}" for kind in ("agree", "differs", "both-refuse", "ws-malformed", "crate-refuses")]
    compared = sum(how["same"] + how["differs"] for how in coverage.values())
    lines.append(f"{compared} fields compared, {sum(how['unlisted'] for how in coverage.values())} shown and unlisted")
    lines.append("explained differences:")
    lines += [f"{times:>7}  {verdict}: {reference}" for (verdict, reference), times in explained.most_common()]
    lines.append(f"{len(unknown)} differences without a row of known.tsv")
    lines += [f"  {what}\t{where}\t(first: {name})" for (what, where), name in list(unknown.items())[:200]]
    summary = "\n".join(lines) + "\n"
    (output / "summary.txt").write_text(summary)
    print(summary, end="")
    if unknown or not compared:
        sys.exit(1)


if __name__ == "__main__":
    main()
