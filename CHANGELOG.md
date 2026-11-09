# Changelog

All notable changes to `oxirush-pfcp` are recorded here.

## 0.1.0 - unreleased

The first version, of TS 29.244 V19.6.0 (2026-06):

- Every message and IE type of N4, N4mb, Sxa, Sxb and Sxc, decoded and encoded back byte
  for byte, and built with `new()` and `with_*()`; a message of its body with
  `Message::node` and `Message::session`. `IE_TYPES` and `ie_type_info()` give the clause
  and the members of each IE type. A field that a value always has is a plain field, as
  the SEID of an F-SEID, and one that its flags, or the value of another field, have or
  not an `Option`: the Redirect Server Address, which a Port redirect has not (§8.2.20),
  and the Reporting Time Info, of a delay tolerant Reporting Suggestion Info alone
  (§8.2.229), whose octets after another value `check()` tells. `FSeid::ipv4()`
  and `FSeid::ipv6()` build an F-SEID of one address, as `FTeid::ipv4()` and
  `FTeid::ipv6()` an F-TEID, and `FTeid::choose_ipv4()` and `FTeid::choose_ipv6()` one
  that the UP function chooses. A value whose octets would read as another value is
  refused by `encode()` and by a tree, and told by `check()` (`Inconsistent`): a field
  read where octets remain that is missing before a later one or unknown octets (the
  C-TAG and S-TAG of MAC Addresses Detected and Removed, whose absent C-TAG field before
  an S-TAG is of no octets, and the Node Type of an FQ-CSID), unknown octets after a
  field that runs to the end of the IE, a field longer than the length that its flags
  give, or shorter with octets after it, a value of bits of a number of octets that it
  may not have, and a Node ID of other octets that are an address or an FQDN.
- `check()`: how a message breaks the tables and clauses on an interface, each deviation
  with its path, its clause and the Cause of the answer; `deviations()` of a value on
  its own. A `Row` is its roles, each with its presence, its interfaces and how many IEs
  of it may be there: the row itself, or the rows that share a field, which the wire
  does not tell apart; `Row::content` the table of a grouped IE in its place, of an IE
  type whose content differs by place. `Row::on` gives what a row is on an interface, or
  on a set of them: its presence, the IEs that a message needs and how many it may have,
  and `None` where it is not: its IEs have no Cause there (§7.6.9), and the conditions of
  the table, which read the rows of the interface alone, do not read them; `Row::is_list`
  whether its tree is a list. A field that its clause encodes as another IE is checked
  as that IE: the Destination Interface of a Remote GTP-U Peer, the C-TAG and S-TAG of
  Outer Header Creation and of MAC Addresses Detected and Removed, and the QFIs of a PMF
  Control Information, which are `SixBits` as a QFI is. A message is checked as its
  receiver reads its octets: `check(m)` is `check(Message::decode(m.encode()))` where they
  decode, however the message holds its IEs, as values or as octets; a Length of an IE
  that keeps them from decoding is told, and the rest checked with it cleared. A Message Length or an IE Length that is
  not the length of what it counts is told, with "Invalid length" in a request and the
  IE that does not frame (§7.6.3, §7.6.7), at any depth: one that runs past its grouped
  IE at that grouped IE, which its receiver cannot read. A false Length whose octets frame
  as other IEs is checked as those, its receiver telling no fault there (§7.6.7).
- With `tree`, a message as a tree that prints as JSON, on oxirush-utils 0.2, whose
  `tree` the crate exports at its root: `{"message": ..., "header": {...}, "ies": {...}}`,
  the header a member of its own, of the fields of §7.2.2 by their names, as `check()`
  names them (`/header/SEID`); and read and edited by path (`paths::select`,
  `paths::set`), and `paths::row_at` names the row and the IE type of the IE at a path,
  which its tables name whether the message has the place or not; with `serde`,
  serialized as its tree. What a message lacks selects nothing, whatever
  the path names below it: a misspelt name below a value or a field that is not there is
  not told, and `set` writes a value that a message lacks whole. An error of
  `Message::from_tree` is at a path that `paths::select` takes. A tree writes each field
  that its value always has; it leaves out a flag that is not set and a field that its
  flags do not have; a value of one field without flags is that field, while it has no
  unknown octets. An IE kept as octets keeps the Length that a tree writes, its
  own too, as the header keeps its Message Length; a Node ID of other octets than an
  address or an FQDN is `{"Node ID Type": ..., "Node ID value": ...}`, apart from
  `{"octets": ...}`, which an IE kept as octets is. A spare octet is written where it is
  set, and is 0 where a tree leaves it out, as the spare bits of the header and of a value. A Flow Description, an
  IPFilterRule, and the URL and the Domain Name of PFD Contents are their text
  (`TextLv16`), or `{"octets": ...}` for octets that are no UTF-8; a Network Instance of
  the labels of a name is that name, a text whatever its characters (`"cafe"`), and
  `{"Network Instance": ...}`, its octets in hexadecimal, otherwise, as are an APN/DNN,
  `{"APN/DNN": ...}`, and the Network Instance field of Remote GTP-U Peer (`NameLv16`);
  a name has labels of 1 to 63 octets, of 253 octets at most;
  `NetworkInstance::from_name()` builds one of a name. The members of a Node ID, as of
  any value, go by their names in any case: `{"fqdn": ...}`.
- With `node`, `Node`, a PFCP entity without I/O: delivery and retransmission (§6.4),
  heartbeat, associations, sessions, load and overload control, and bundles (§6.5). A
  request that names another's session or association, as another SMF of a set sends
  (§5.22), goes to the caller as `Received::stranger`, and the one of SEID 0 that hands a
  session over is answered as one of the adopted session (`respond_as`); one that says
  its priority has it in `Received::priority`. An IPv4 peer that a socket of both
  families gives at its IPv4-mapped address is its IPv4 address. A probe's answer
  (`respond_message`) changes the node as its peer reads the datagram sent, by the one
  reader of `handle_datagram`: of the bundling that they agreed (§6.5), a message that
  the peer takes as the response of another of its requests answers that request, and a
  Version Not Supported Response ends every request of the peer (§7.2.1A); `respond` to a
  request so answered or ended is `NodeError::Answered`, and sends nothing.
- With `endpoint`, `Endpoint`, a node on a Tokio UDP socket, and its `Handle`.
- A request that ends without its response says why in a `Failure`, a timeout one of
  them: `Event::Failed`, `EndpointError::Failed`.
- `no_std` with an allocator, but for `endpoint`; Rust 1.88.
