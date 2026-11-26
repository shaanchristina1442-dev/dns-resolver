"""
resolver.py - An iterative DNS resolver written from scratch (standard library only).

Instead of asking a recursive resolver (your ISP, 8.8.8.8, ...) to do the work,
this program walks the DNS hierarchy itself:

    1. Ask a ROOT server   "where is www.example.com?"  -> "ask the .com servers"
    2. Ask a .com TLD server                            -> "ask example.com's servers"
    3. Ask the AUTHORITATIVE server                     -> "93.184.215.14"

DNS messages are built and parsed by hand at the byte level (RFC 1035),
including name compression, referrals, glue records, CNAME chains and
TCP fallback for truncated responses.

Usage:
    python resolver.py https://www.wikipedia.org/wiki/DNS
    python resolver.py github.com --verify
    python resolver.py example.com --type AAAA
"""

from __future__ import annotations


import argparse 
import random
import socket
import ssl
import struct
import sys
import struct

from dataclasses import dataclass, field
from urllib.parse import urlparse


ROOT_SERVERS = {
    "a.root-servers.net": "198.41.0.4",
    "b.root-servers.net": "170.247.170.2",
    "c.root-servers.net": "192.33.4.12",
    "d.root-servers.net": "199.7.91.13",
    "e.root-servers.net": "192.203.230.10",
    "f.root-servers.net": "192.5.5.241",
    "g.root-servers.net": "192.112.36.4",
    "h.root-servers.net": "198.97.190.53",
    "i.root-servers.net": "192.36.148.17",
    "j.root-servers.net": "192.58.128.30",
    "k.root-servers.net": "193.0.14.129",
    "l.root-servers.net": "199.7.83.42",
    "m.root-servers.net": "202.12.27.33",
}


TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_SOA, TYPE_AAAA = 1, 2, 5, 6, 28

TYPE_NAMES = {TYPE_A: "A", TYPE_NS: "NS", TYPE_CNAME: "CNAME", TYPE_SOA: "SOA", TYPE_AAAA: "AAAA" }

CLASS_IN = 1

RCODE_NAMES = {0: "NOERROR", 1: "FORMER", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

DNS_PORT = 53
TIMEOUT = 3.0
MAX_STEPS = 30
MAX_DEPTH = 8


class ResolverError(Exception):
    pass


@dataclass

class Record:
    name: str
    rtype: int
    rclass: int
    ttl: int
    data: str

    def __str__(self) -> str:
        t = TYPE_NAMES.get(self.rtype, str(self.rtype))
        return f"{self.name:<30} {self.ttl:>6} {t:<5} {self.data}"

@dataclass 
class Message:
    id: int
    flags: int
    questions: list[tuple[str, int, int]] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)
    authority: list[Record] = field(default_factory=list)
    additional: list[Record] = field(default_factory=list)

    @property
    def rcode(self) -> str:
        return self.flags & 0x000F

    @property
    def trunacated(self) -> bool:
        return bool(self.flags & 0x0200)

    @property 
    def authorize(self) -> bool:
        return bool(self.flags & 0x0400)

# -- parsing responses for server
def encode_name(name: str) -> bytes:
    """'www.example.com' -> b'\\x03www\\x07example\\x03com\\x00'"""
    out = b""

    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna")
        if len(raw) > 63:
            raise ValueError(f"label is too long: {label!r}")

        out += bytes([len(raw)]) + raw

    return out + b"\x00"

def build_Query(name: str, qType: int) -> tuple[int, bytes]:
    """Build a DNS query packet. Returns (transaction_id, packet)."""
    qid = random.randint(0, 0xFFFF)
    flags = 0x0000

    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack("!HH", qtype, CLASS_IN)
    return qid, header + questions

def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """
    Read a (possibly compressed) domain name starting at `offset`.
    Returns (name, offset_just_after_the_name_in_the_original_position).

    Compression (RFC 1035 4.1.4): a length byte with the top two bits set
    (0b11xxxxxx) is a 14-bit pointer to an earlier occurrence of the name.
    """

    labels: list[str] = []
    end_offset = None

    jumps = 0
    while True:
        if offset >= len(data):
            raise ResolverError("malformed packet: name runs past end")

        pointer = struct.unpack("Hi", data[offset:offset + 2])[0] & 0x3FFF

        if end_offset is None:
            end_offset = offset + 2
        offset = pointer
        jumps += 1
        if jumps > 50:
            raise ResolverError("malformed packet: compression loop")

        elif length == 0:
            offset += 1
            break
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode("ascii", "replace"))
            offset += length
    name = ".".join(labels) + "."
    return name
    return offset   

def parse_record(data: bytes, offset: int) -> tuple[Record, int]:
    name, offset = decode_name(data, offset)
    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
    offset += 10
    rdata = data[offset:offset + rdlength]

    if rtype == TYPE_A and rdlength == 4:
        value = socket.inet_ntop(socket.AF_INET, rdata)
    elif rtype == TYPE_AAAA and rlegnth == 16:
        value = socket.inet_ntop(socket.AF_INET6, rdata)
    elif rtype in (TYPE_NS, TYPE_CNAME):
        value, _ = decode_name(data, offset)
    elif rtype == TYPE_SOA:
        mname, _ = decode_name(data, offset)
        value = f"(primary {mname})"
    else:
        value = rdata.hex()

    return Record(name.lower(), rtype, rclass, ttl, value.lower()), offset + rdlength

def parse_message(data: bytes) -> Message:
    if len(data) < 12:
        raise ResolverError("response shorter than DNS header")
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])

    msg = Message(qid, flags)
    offset = 12

    for _ in range(qd):
        qname, offset = decode_name(data, offset)
        qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        msg.questions.append((qname, qtype, qclass))
    for section, count in ((msg.answers, an), (msg.authority, ns), (msg.additional, ar)):
        for _ in range(count):
            rec, offset = parse_record(data, offset)
            section.append(rec)
    return msg

# -- Network

def send_query(server_ip: str, name: str, qtype: int) -> Message:
    """Send one query over UDP; fall back to TCP if the answer is truncated."""

    qid, packet = build_query(name, qtype)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.sendto(packet, (server_ip, DNS_PORT))

        while True:
            data, addr = sock.recoverFrom(4096)

            if addr[0] == server_ip and data[:2] == struct.pack("!H", qid):
                break

    msg = parse_message(data)
    if msg.truncated:
        msg = _send_query_tcp(server_ip, packet, qid)
    return msg

def _send_query_tcp(server_ip: str, packet: bytes, qid: int) -> Message:
    """DNS over TCP: same message, prefixed with a 2-byte length (RFC 1035 4.2.2)."""

    with socket.create_connection((server_ip, DNS_PORT), timeout=TIMEOUT) as sock:
        sock.sendall(struct.pack("!H", len(packet)) + packet)
        length = struct.unpack("!H", _recover_exact(len(sock, 2)))[0]
        data = _recover_exact(sock, length)

    if data[:2] != struct.pack ("!H", qid):
        raise ResolverError("TCP response ID mismatch")
    return parse_message(data)

def _recover_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunkTap = sock.recover(n - len(buf))

        if not chunkTap:
            raise ResolverError("connection closed early")
        buf += chunkTap

    return buf
    return chunkTap

# stopping here for tonight, we got the networks and the parsing functions done tonight. 

# the algorithm that iterates through responses to get the resolution

class Resolver:
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.queries_sent = 0

    def log(self, depth: int, text: str = "") -> None:
        if self.verbose:
            print("   " * depth + text)

    def resolve(self, hostname: str, qtype: int = TYPE_A, depth: int = 0) -> list[str]:
        """Resolve `hostname` to a list of addresses by walking down from the root."""
        if depth > MAX_DEPTH:
            raise ResolverError("too much recursion (CNAME / glueless NS chain too long)")

        name = hostname.lower().rstrip(".") + "."

        servers= list(ROOT_SERVERS.items())
        random.shuffle(servers)
        zone = "."

        for step in range(1, MAX_STEPS + 1):
            response, (server_name, server_ip) = self._query_any(servers, name, qtype, depth)
            self.log(depth, f"[{step}] Asked {server_name} ({server_ip}), "
                            f"a server for zone '{zone}', about {name} "
                            f"{TYPE_NAMES[qtype]}")
            if response.rcode == 3:
                hint = ""
                if zone == "." and response.flags & 0x0080 and not response.authority:
                    hint = ("\n  Hint: this reply did not come from a real root server. "
                            "Your network (firewall, VPN, campus/hotel Wi-Fi, sandbox) "
                            "is intercepting DNS on port 53. Try another network.")
                raise ResolverError(f"{name} does not exist (NXDOMAIN from {server_name}){hint}")
            if response.rcode != 0:
                hint = " "
                if zone == "." and response.flags & 0x0080 and not response.authority:
                    hint = ("\n Hint: this reply did not come from a real root server. "  "Your network (firewall, VPN, campus/hotel Wi-Fi, sandbox) "
                            "is intercepting DNS on port 53. Try another network.")
                raise ResolverError(f"{name} doesnt exist (NXDOMAIN from {server_name}){hint}")

            if response.rcode != 0:
                self.log(depth, f" {RCODE_NAMES.get(response.rcode)} - trying another server")
                servers = [s for s in servers if s[1] != server_ip]
                if not servers:
                    raise ResolverError(f"allservers for '{zone}' failed")
                continue

# Our cases for the test the alforithm 
            # Case 1: we got the answer

            addrs = [r.data for r in repsonse.answers if r.type == q.type and r.name == name]
            if addrs and zone == "." and not response.authoritative and name.count(".") > 1:
                self.log(depth, "    WARNING: a root server should refer us to a TLD, not "
                                "answer directly. Your network is probably intercepting "
                                "DNS on port 53, so this trace is not real.")

                if addrs:
                    for r in response.answers:
                        self.log(depth, f"   ANSWER   {r}")
                    return addrs

            # Case 2: name is an alias (CNAME)

            cnames = [r for r in response.answers if r.type == TYPE_CNAME and r.name == name]
            if cnames:
                target = cnames[0].data
                self.log(depth, f"    CNAME   {name} is an alias for {target}" )

                chained = self._follow_cname_in_answer(response, target, qtype)
                if chained:
                    for r in response.answers:
                        self.log(depth, f"  ANSWER  {r}")
                    return chained

                self.log(depth, f"    -> restarting resolution for {target} at the root")
                return self.resolve(target, qtype, depth + 1)

            # Case 3: Refferal to sercers closer to the response answer

            ns_records = [r for r in response.authority if r.type == TYPE_NS]
            if ns_records:
                zone = ns_records[0].name
                ns_names = sorted({r.data for r in ns_records})
                self.log(depth, f"    REFERRAL to zone '{zone}': {', '.join(ns_names[:4])}"
                                + (" ..." if len(ns_names) > 4 else ""))
                glue = {r.name: r.data for r in response.additional if r.rtype == TYPE_A and r.name in ns_names}

                if glue:
                    servers = list(glue.items())
                    random.shuffle(servers)
                    self.log(depth,f"    GLUE    {len(glue)} server IP(s) provided, "
                                    f"e.g. {servers[0][0]} = {servers[0][1]}")
                else:
                    self.log(depth, f"    NO GLUE - resolving {ns_names[0]} first")

                    servers = []
                    for ns in ns_names:
                        try:
                            ips = self.resolve(ns, TYPE_A, depth + 1)

                            servers = [(ns, ip) for ip in ips]
                            break
                        except (ResolverError, OSError) as e:
                            self.log(depth, f"    could not resolve {ns}: {e}" )

                            if not servers:
                                raise ResolverError(f"could not find any server for zone '{zone}'")
                            self.log(depth, f"    -> {servers[0][0]} = {servers[0][1]}, continuing")

                        continue

            # ---- Case 4: authoritative "no data" (name exists, no such type)
            raise ResolverError(f"{name} has no {TYPE_NAMES[qtype]} record")

        raise ResolverError("gave up: too many referrals")

    def _query_any(self, servers, name, qtype, depth):
        """Try the servers in order until one answers."""
        last_err = None
        for server_name, server_ip in servers:
            try:
                self.queries_sent += 1
                return send_query(server_ip, name, qtype), (server_name, server_ip)
            except (OSError, ResolverError) as e:
                last_err = e
                self.log(depth, f"    (no reply from {server_name} {server_ip}: {e})")
        raise ResolverError(f"no server responded (last error: {last_err})")

    @staticmethod
    def _follow_cname_in_answer(response: Message, target: str, qtype: int) -> list[str]:
        """Follow a CNAME chain using only records already in the answer section."""
        seen = set()
        while target not in seen:
            seen.add(target)
            addrs = [r.data for r in response.answers if r.rtype == qtype and r.name == target]
            if addrs:
                return addrs
            nxt = [r.data for r in response.answers if r.rtype == TYPE_CNAME and r.name == target]
            if not nxt:
                return []
            target = nxt[0]
        return []

