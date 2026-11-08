# Security policy

## Reporting a vulnerability

Report a vulnerability in private, through **Report a vulnerability** on the
[Security tab](https://github.com/linouxis9/oxirush-pfcp/security) of the
repository. Please do not open a public issue for it.

Say what the input is and what happens: the octets of the datagram, the
function that was called, and the version or the commit of the crate. A
datagram that makes a decoder or a node panic, loop or allocate without bound
is a vulnerability, and so is a node that a peer can make answer for another
peer.

A decoded message takes up to 191 times its octets, in its lists of grouped
IEs: a datagram of 64 KiB, some 12.5 MB (the test `allocation` measures it). An
`Endpoint` bounds its queue of requests by what they take
(`Queues::incoming_octets`); a caller that keeps decoded messages itself bounds
them so.

## Supported versions

The crate is not on crates.io yet: the `main` branch receives the fixes.
