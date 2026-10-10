#!/usr/bin/env python3
"""Bounded, non-authenticating VPN endpoint inventory and fingerprinting."""

import argparse
import ipaddress
import json
import math
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

TCP_PORTS = (1194, 1723, 443, 8443, 10443)
UDP_PORTS = (1194, 500, 4500, 1701)
HTTPS_PORTS = (443, 8443, 10443)
MAX_HOSTS = 64
MAX_THREADS = 16
MAX_TIMEOUT = 30.0
MAX_BODY_BYTES = 2048
MIN_REQUESTS_PER_SECOND = 0.1
MAX_REQUESTS_PER_SECOND = 5.0
DEFAULT_REQUESTS_PER_SECOND = 2.0
HOST_LABEL = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

VPN_PAGE_SIGNATURES = (
    {
        "vendor": "cisco_anyconnect",
        "path": "/+CSCOE+/logon.html",
        "markers": ("webvpn", "cscoe", "cisco secure"),
    },
    {
        "vendor": "fortinet",
        "path": "/remote/login",
        "markers": ("fortinet", "fortigate"),
    },
    {
        "vendor": "pulse_secure",
        "path": "/dana-na/auth/url_default/welcome.cgi",
        "markers": ("pulse secure",),
    },
    {
        "vendor": "palo_alto_globalprotect",
        "path": "/global-protect/login.esp",
        "markers": ("globalprotect", "global protect", "palo alto networks"),
    },
    {
        "vendor": "f5_big_ip",
        "path": "/my.policy",
        "markers": ("big-ip", "bigip", "f5 networks"),
    },
)


def validate_host(host: str) -> str:
    """Accept a plain IPv4 address or DNS hostname, never a URL or port."""
    if not host or host != host.strip() or any(char in host for char in "/\\:@[]?#"):
        raise ValueError(f"invalid target host: {host!r}")
    try:
        return str(ipaddress.IPv4Address(host))
    except ipaddress.AddressValueError:
        try:
            hostname = host.rstrip(".").encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError(f"invalid target host: {host!r}") from exc
        if len(hostname) > 253 or not all(HOST_LABEL.fullmatch(label) for label in hostname.split(".")):
            raise ValueError(f"invalid target host: {host!r}")
        return hostname.lower()


def validate_positive_number(value: str, name: str, maximum: float) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{name} must be a number") from exc
    if not math.isfinite(number) or number <= 0 or number > maximum:
        raise argparse.ArgumentTypeError(f"{name} must be greater than 0 and at most {maximum:g}")
    return number


class RequestRateLimiter:
    """Apply one aggregate minimum interval between network probes."""

    def __init__(self, requests_per_second: float):
        self._interval = 1.0 / requests_per_second
        self._lock = threading.Lock()
        self._next_request = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delay = self._next_request - now
            if delay > 0:
                time.sleep(delay)
            self._next_request = time.monotonic() + self._interval


def tcp_probe(host: str, port: int, timeout: float) -> dict:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"state": "reachable", "evidence": "TCP connection accepted"}
    except ConnectionRefusedError:
        return {"state": "closed"}
    except (socket.timeout, TimeoutError):
        return {"state": "no_response", "error": "connection timed out"}
    except OSError as exc:
        return {"state": "error", "error": str(exc)}


def udp_probe(host: str, port: int, timeout: float) -> dict:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b"\x00" * 4, (host, port))
            data, _ = sock.recvfrom(512)
        return {
            "state": "response_received",
            "response_bytes": len(data),
            "evidence": "UDP response received; service and protocol are unconfirmed",
        }
    except (socket.timeout, TimeoutError):
        return {"state": "no_response"}
    except OSError as exc:
        return {"state": "error", "error": str(exc)}


class SameOriginRedirectHandler(HTTPRedirectHandler):
    def __init__(self, host: str, port: int, limiter: RequestRateLimiter):
        super().__init__()
        self.host = host.lower()
        self.port = port
        self.limiter = limiter

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = urlsplit(newurl)
        destination_port = destination.port or (443 if destination.scheme == "https" else 80)
        if (
            destination.scheme != "https"
            or (destination.hostname or "").lower() != self.host
            or destination_port != self.port
        ):
            raise URLError("redirect outside the requested HTTPS origin was blocked")
        self.limiter.wait()
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def target_netloc(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def check_https_pages(
    host: str, port: int, timeout: float, limiter: RequestRateLimiter
) -> tuple[list, list, list]:
    fingerprints = []
    observations = []
    errors = []
    opener = build_opener(SameOriginRedirectHandler(host, port, limiter))

    for signature in VPN_PAGE_SIGNATURES:
        url = f"https://{target_netloc(host, port)}{signature['path']}"
        limiter.wait()
        request = Request(url, headers={"User-Agent": "vpn-probe/1.0"})
        try:
            response = opener.open(request, timeout=timeout)
        except HTTPError as exc:
            response = exc
        except (URLError, OSError, TimeoutError, ValueError) as exc:
            errors.append({"probe": signature["vendor"], "error": str(exc)})
            continue

        try:
            status = response.code
            observations.append({"probe": signature["vendor"], "path": signature["path"], "status": status})
            if status >= 500:
                errors.append({"probe": signature["vendor"], "error": f"HTTP status {status}"})
            body = response.read(MAX_BODY_BYTES).decode("utf-8", errors="replace").lower()
        except (OSError, URLError, TimeoutError) as exc:
            errors.append({"probe": signature["vendor"], "error": str(exc)})
            continue
        finally:
            response.close()

        marker = next((item for item in signature["markers"] if item in body), None)
        if marker:
            fingerprints.append({
                "vendor": signature["vendor"],
                "url": url,
                "status": status,
                "evidence": f"vendor-specific page marker: {marker}",
            })

    return fingerprints, observations, errors


def scan_host(host: str, timeout: float, limiter: RequestRateLimiter) -> dict:
    result = {
        "host": host,
        "ports": {},
        "https_observations": [],
        "fingerprints": [],
        "errors": [],
        "limitations": "Port reachability and UDP responses do not identify a VPN service or protocol.",
    }

    for port in TCP_PORTS:
        limiter.wait()
        observation = tcp_probe(host, port, timeout)
        result["ports"][f"tcp/{port}"] = observation
        if observation.get("state") == "error":
            result["errors"].append({"probe": f"tcp/{port}", "error": observation["error"]})

    for port in UDP_PORTS:
        limiter.wait()
        observation = udp_probe(host, port, timeout)
        result["ports"][f"udp/{port}"] = observation
        if observation.get("state") == "error":
            result["errors"].append({"probe": f"udp/{port}", "error": observation["error"]})

    for port in HTTPS_PORTS:
        if result["ports"][f"tcp/{port}"]["state"] != "reachable":
            continue
        matches, observations, errors = check_https_pages(host, port, timeout, limiter)
        result["fingerprints"].extend(matches)
        result["https_observations"].extend(
            {"port": port, **observation} for observation in observations
        )
        result["errors"].extend(
            {"probe": f"https/{port}/{error['probe']}", "error": error["error"]}
            for error in errors
        )

    return result


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Bounded, non-authenticating VPN endpoint inventory (authorized targets only)."
    )
    parser.add_argument("hosts", nargs="+", help="Plain IPv4 addresses or DNS hostnames")
    parser.add_argument("--threads", type=int, default=4, help=f"Concurrent hosts (1-{MAX_THREADS}, default: 4)")
    parser.add_argument(
        "--timeout",
        type=lambda value: validate_positive_number(value, "timeout", MAX_TIMEOUT),
        default=5.0,
        help=f"Per-probe timeout in seconds (greater than 0, at most {MAX_TIMEOUT:g}; default: 5)",
    )
    parser.add_argument(
        "--rate",
        type=lambda value: validate_positive_number(value, "rate", MAX_REQUESTS_PER_SECOND),
        default=DEFAULT_REQUESTS_PER_SECOND,
        help=f"Aggregate probes per second ({MIN_REQUESTS_PER_SECOND:g}-{MAX_REQUESTS_PER_SECOND:g}, default: 2)",
    )
    parser.add_argument("--out", help="Write JSON results to this file (default: stdout)")
    args = parser.parse_args(argv)

    if not 1 <= args.threads <= MAX_THREADS:
        parser.error(f"--threads must be between 1 and {MAX_THREADS}")
    try:
        args.hosts = list(dict.fromkeys(validate_host(host) for host in args.hosts))
    except ValueError as exc:
        parser.error(str(exc))
    if len(args.hosts) > MAX_HOSTS:
        parser.error(f"at most {MAX_HOSTS} hosts may be scanned at once")
    if args.rate < MIN_REQUESTS_PER_SECOND:
        parser.error(f"--rate must be at least {MIN_REQUESTS_PER_SECOND:g}")
    return args


def main(argv=None):
    args = parse_args(argv)
    limiter = RequestRateLimiter(args.rate)
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = list(executor.map(lambda host: scan_host(host, args.timeout, limiter), args.hosts))

    output = json.dumps(results, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as output_file:
            output_file.write(output + "\n")
    else:
        print(output)


if __name__ == "__main__":
    main()
