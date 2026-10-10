<div align="center">
  <img src="./banner.svg" alt="vpn-probe" width="800">
</div>

# vpn-probe

`vpn-probe` is a bounded, non-authenticating inventory tool for VPN-related
network endpoints on targets you are authorized to assess. It records TCP
connection reachability and UDP responses, and checks a small set of HTTPS
login-page paths for vendor-specific page markers. It does not log in, submit
credentials, guess passwords, exploit services, or attempt evasion.

## Usage

```bash
python vpn_probe.py --help
python vpn_probe.py vpn.example.com 192.0.2.10 --timeout 3 --threads 4 --rate 2
python vpn_probe.py vpn.example.com --out results.json
```

Python 3.9 or later is required. The tool uses only the Python standard library.
Targets must be plain IPv4 addresses or DNS hostnames; URLs, ports, IPv6
addresses, and malformed hostnames are rejected. At most 64 unique hosts can be
provided per run. Concurrency is limited to 1-16 hosts, each network operation
has a timeout no greater than 30 seconds, and the aggregate probe rate is
configurable from 0.1 to 5 probes per second (default: 2). Socket and HTTPS
requests use that timeout; DNS lookup duration remains governed by the system
resolver.

Results are JSON written to standard output or the file supplied with `--out`.
Each host contains individual TCP/UDP observations, HTTP statuses for reachable
HTTPS paths, any vendor fingerprints, and explicit transport/HTTP errors. TLS
certificate and hostname verification remain enabled. Redirects to a different
HTTPS origin or port are blocked. HTTPS response bodies are read up to 2,048
bytes.

## Interpretation and limitations

A successful TCP connection means only that a TCP peer accepted a connection.
A UDP response means only that a datagram was received; no response does not
prove a UDP service is closed. Neither observation identifies a VPN protocol or
vendor. A vendor is reported only when the expected endpoint response contains
one of the corresponding product-specific markers; generic login text is not
enough. These lightweight observations are not a vulnerability assessment,
service guarantee, or proof that a VPN is configured or usable. TLS failures
and other probe failures are reported rather than bypassed.

Use only against systems for which you have explicit authorization. No external
targets are contacted by the test suite.

## Tests

Run the offline unit tests with:

```bash
python -m unittest discover -s tests -v
```

**Omar Khalid** — [omareldemery.com](https://omareldemery.com)
