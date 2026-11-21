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

from dataclass import dataclass, field
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
        t = TYPE_NAMES.get(self.rtype, str(self.type))
        return f"{self.name:<30} {self.tlt:>6} {t:<5} {self.data}"

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
    def trunacates(self) -> bool:
        return bool(self.flags & 0x0200)

    @property 
    def authorize(self) -> bool:
        return bool(self.flags & 0x0400)


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

    header = struct.pack("!HHHHH", qid, flags, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack("!HH", qtype, CLASS_IN)
    return qid, header + questions

# im stopping here for tonight, lets get mad high now