# Iterative DNS Resolver (from scratch, in Python)

A command-line DNS resolver that turns a URL into an IP address **without asking
anyone else to do the work**. It starts at the internet's root servers and follows
referrals down the hierarchy, the same way a recursive resolver like 8.8.8.8 does
internally. DNS packets are built and parsed by hand at the byte level, using only
Python's standard library.

```
$ python resolver.py https://www.wikipedia.org/wiki/DNS --verify
Resolving www.wikipedia.org (A) iteratively, starting at the root servers

[1] Asked a.root-servers.net (198.41.0.4), a server for zone '.', about www.wikipedia.org. A
    REFERRAL to zone 'org.': a0.org.afilias-nst.info., a2.org.afilias-nst.info., ...
    GLUE    6 server IP(s) provided, e.g. a0.org.afilias-nst.info. = 199.19.56.1
[2] Asked a0.org.afilias-nst.info. (199.19.56.1), a server for zone 'org.', about www.wikipedia.org. A
    REFERRAL to zone 'wikipedia.org.': ns0.wikimedia.org., ns1.wikimedia.org., ns2.wikimedia.org.
    GLUE    3 server IP(s) provided, e.g. ns0.wikimedia.org. = 208.80.154.238
[3] Asked ns0.wikimedia.org. (208.80.154.238), a server for zone 'wikipedia.org.', about www.wikipedia.org. A
    CNAME   www.wikipedia.org. is an alias for dyna.wikimedia.org.
    -> restarting resolution for dyna.wikimedia.org. at the root
    ...
Result: www.wikipedia.org -> 208.80.154.224   (6 queries sent)

Verifying: connecting straight to 208.80.154.224:443 and asking for www.wikipedia.org
  TLS OK    certificate for '*.wikipedia.org', issued by DigiCert Inc
  HTTP      HTTP/1.1 301 Moved Permanently
  Verified: 208.80.154.224 serves a valid certificate for www.wikipedia.org.
```
*(This sample shows what the output looks like. Server names and IPs will differ on your run.)*

## Features

- **Iterative resolution** from the 13 root servers, through TLD servers, down to the domain's authoritative servers
- **Hand-written DNS wire format** (RFC 1035): builds query headers and questions, and parses all four response sections
- **Name compression**: decodes compression pointers and guards against pointer loops in malformed packets
- **Glue records**: uses the IPs that come with a referral when present
- **Glueless referrals**: when a domain's name servers live under another TLD, it resolves them first, recursively
- **CNAME chains**: follows aliases inside one answer, or restarts at the root if needed
- **TCP fallback** when a UDP response is truncated (TC bit)
- **A and AAAA** (IPv4 and IPv6) lookups
- **Fault tolerance**: per-server timeouts, retries other servers, ignores packets with a mismatched ID or sender
- **HTTPS verification**: connects to the resolved IP directly and checks the site's TLS certificate
- **Offline test suite**: 11 unit tests that simulate root, TLD and authoritative servers with hand-built packets

## Usage

Needs Python 3.9 or newer. No dependencies.

```bash
python resolver.py <url-or-hostname> [--type A|AAAA] [--verify] [-q]

python resolver.py https://github.com/explore     # full URLs are fine
python resolver.py example.com --type AAAA        # IPv6
python resolver.py www.wikipedia.org --verify     # prove the IP is correct
python resolver.py github.com -q                  # just print the IP

python -m unittest -v                             # run the tests
```

> **Network note:** some networks (campus Wi-Fi, corporate firewalls, VPNs, cloud
> sandboxes) intercept all port-53 traffic and answer it themselves. The resolver
> detects the common signs and prints a warning. If you see one, switch networks
> (a phone hotspot works well).

## Checking the IP in a browser

**Option 1: type the IP.** Paste `http://<ip>/` into the address bar. This works for
sites hosted on their own server. Large sites host many domains on shared IPs and
need the hostname to know which site you want. For those you'll get an error page
or a certificate warning, even though the IP is correct. That makes a good point to
explain in your class demo.

**Option 2: hosts file (works for every site).** This tells your computer to skip DNS
for one name and use your IP. The site loads normally with a valid padlock, so you
know the traffic went to the IP you found.

| OS | File |
|---|---|
| Windows | `C:\Windows\System32\drivers\etc\hosts` (open Notepad as Administrator) |
| macOS / Linux | `/etc/hosts` (`sudo nano /etc/hosts`) |

Add a line such as `208.80.154.224  www.wikipedia.org`, save, and reload the page.
Remove the line afterwards.

**Option 3: `--verify`.** The script does the same check itself. It opens a TLS
connection to the IP, asks for the hostname, and confirms the certificate is valid
for that site and signed by a trusted authority.

## How it works

```
 you ──► root server (.)        "Ask the .com servers, here are their IPs"     (referral + glue)
     ──► TLD server (com.)      "Ask example.com's servers at 199.43.135.53"   (referral + glue)
     ──► authoritative server   "www.example.com = 93.184.215.14"              (answer)
```

Each query is a 12-byte header plus a question. The header has the RD
(recursion desired) flag **off**, so each server answers only what it knows and
does not look up the rest for us. The resolver handles each reply in one of four ways:

1. **Answer**: the record we asked for. Done.
2. **CNAME**: the name is an alias. Follow it.
3. **Referral**: NS records in the authority section. Move one level down.
4. **NXDOMAIN / no data**: report an error.

## Resume bullet

> **Iterative DNS Resolver** (Python, sockets): Built a DNS resolver from scratch
> that resolves domains by querying root, TLD and authoritative name servers directly.
> Wrote the RFC 1035 binary wire format by hand (including name compression), and
> handled glueless referrals, CNAME chains, UDP truncation with TCP fallback, and
> IPv6. Checked results with a TLS certificate test and an offline unit-test suite
> that simulates the DNS hierarchy.
