#!/usr/bin/env python3
"""
VPN Probe — VPN Endpoint Discovery & Fingerprinting Tool
Identifies VPN technology (OpenVPN, IKEv1/v2, Cisco, Fortinet) and checks for default configs.
Author: Omar Khalid (amooryx) | github.com/amooryx/vpn-probe
AUTHORIZED USE ONLY.
"""

import argparse
import json
import socket
import struct
import sys
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

VPN_PORTS = {
    1194: ("OpenVPN", "UDP/TCP"),
    500:  ("IKE/IPSec", "UDP"),
    4500: ("NAT-T IPSec", "UDP"),
    1723: ("PPTP", "TCP"),
    1701: ("L2TP", "UDP"),
    443:  ("SSL VPN (Cisco/Fortinet/Pulse)", "TCP"),
    8443: ("SSL VPN Alt", "TCP"),
    10443:("Pulse Secure", "TCP"),
}

SSL_VPN_PATHS = {
    "cisco_anyconnect": ["/+CSCOE+/logon.html", "/+CSCOE+/portal.html"],
    "fortinet": ["/remote/login", "/remote/logincheck", "/remote/info"],
    "pulse_secure": ["/dana-na/auth/url_default/welcome.cgi"],
    "palo_alto": ["/global-protect/login.esp", "/global-protect/getconfig.esp"],
    "f5_big_ip": ["/my.policy", "/vdesk/hangup.php3"],
    "openvpn_web": ["/vpninfo/users/0"],
}

def tcp_connect(host: str, port: int, timeout: float = 5) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False

def udp_probe(host: str, port: int, payload: bytes, timeout: float = 3) -> bytes:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(payload, (host, port))
        data = s.recv(512)
        s.close()
        return data
    except Exception:
        return b""

def ike_v1_probe(host: str, port: int = 500) -> dict:
    """Send IKEv1 main mode initiate and check for IKE response."""
    # IKEv1 SA_INIT: simplified probe (no crypto negotiation)
    cookie_i = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    cookie_r = b"\x00" * 8
    header   = cookie_i + cookie_r + b"\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x1c"
    resp     = udp_probe(host, port, header)
    if len(resp) >= 28:
        return {"protocol": "IKEv1", "response_bytes": len(resp), "open": True}
    return {"protocol": "IKEv1", "open": False}

def check_ssl_vpn(host: str, port: int) -> list[dict]:
    """Check for known SSL VPN login pages."""
    findings = []
    base_url = f"https://{host}:{port}"
    for vendor, paths in SSL_VPN_PATHS.items():
        for path in paths:
            url = base_url + path
            try:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
                    body = resp.read(2048).decode(errors="ignore").lower()
                    if any(kw in body for kw in ["login", "password", "vpn", "connect", "sign in"]):
                        findings.append({
                            "vendor": vendor, "url": url, "status": resp.status,
                            "note": f"SSL VPN login page detected: {vendor}",
                        })
                        print(f"  [!!!] {vendor.upper()} VPN login found: {url}")
                        break
            except urllib.error.HTTPError as e:
                if e.code in (200, 302):
                    findings.append({"vendor": vendor, "url": url, "status": e.code})
            except Exception:
                pass
    return findings

def scan_host(host: str, timeout: float) -> dict:
    result = {"host": host, "vpn_ports": {}, "ssl_vpn": [], "ike": {}}

    for port, (service, proto) in VPN_PORTS.items():
        if "TCP" in proto:
            open_ = tcp_connect(host, port, timeout)
        else:
            # Try UDP by sending minimal payload
            resp = udp_probe(host, port, b"\x00" * 4, timeout=2)
            open_ = len(resp) > 0
        if open_:
            result["vpn_ports"][port] = {"service": service, "proto": proto}
            print(f"  [+] {host}:{port} {service} ({proto})")

    if result["vpn_ports"].get(500):
        result["ike"] = ike_v1_probe(host, 500)

    for port in [443, 8443, 10443]:
        if result["vpn_ports"].get(port):
            result["ssl_vpn"].extend(check_ssl_vpn(host, port))

    return result

def main():
    parser = argparse.ArgumentParser(
        description="VPN Probe — VPN Endpoint Fingerprinting (Authorized use only)",
    )
    parser.add_argument("hosts",     nargs="+", help="Target hosts/IPs")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--out",     help="Output JSON file")
    args = parser.parse_args()

    print(f"[*] VPN probing: {len(args.hosts)} hosts")
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = {exe.submit(scan_host, h, args.timeout): h for h in args.hosts}
        for fut in futures:
            r = fut.result()
            results.append(r)

    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
