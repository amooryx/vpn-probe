from io import BytesIO
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import vpn_probe


class HostValidationTests(unittest.TestCase):
    def test_accepts_ipv4_and_hostname(self):
        self.assertEqual(vpn_probe.validate_host("192.0.2.10"), "192.0.2.10")
        self.assertEqual(vpn_probe.validate_host("Vpn.Example.COM."), "vpn.example.com")
        self.assertEqual(vpn_probe.validate_host("vpn.exämple.com"), "vpn.xn--exmple-cua.com")

    def test_rejects_url_and_malformed_host(self):
        for value in ("https://vpn.example.com", "vpn.example.com:443", "bad host", "-vpn.example"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    vpn_probe.validate_host(value)

    def test_cli_rejects_out_of_bound_threads(self):
        with self.assertRaises(SystemExit):
            vpn_probe.parse_args(["vpn.example", "--threads", "17"])

    def test_cli_rejects_out_of_bound_rate(self):
        with self.assertRaises(SystemExit):
            vpn_probe.parse_args(["vpn.example", "--rate", "5.1"])
        with self.assertRaises(SystemExit):
            vpn_probe.parse_args(["vpn.example", "--rate", "nan"])
        with self.assertRaises(SystemExit):
            vpn_probe.parse_args(["vpn.example", "--rate", "0.01"])


class ProbeTests(unittest.TestCase):
    def test_tcp_connection_reports_reachability_not_vpn_type(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        with patch.object(vpn_probe.socket, "create_connection", return_value=connection):
            result = vpn_probe.tcp_probe("vpn.example", 443, 1)
        self.assertEqual(result, {"state": "reachable", "evidence": "TCP connection accepted"})

    def test_tcp_timeout_is_explicit(self):
        with patch.object(vpn_probe.socket, "create_connection", side_effect=TimeoutError):
            result = vpn_probe.tcp_probe("vpn.example", 443, 1)
        self.assertEqual(result["state"], "no_response")
        self.assertIn("timed out", result["error"])

    def test_udp_timeout_does_not_claim_closed(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recvfrom.side_effect = TimeoutError
        with patch.object(vpn_probe.socket, "socket", return_value=sock):
            result = vpn_probe.udp_probe("vpn.example", 500, 1)
        self.assertEqual(result, {"state": "no_response"})

    def test_http_reads_are_capped_and_generic_login_is_not_a_fingerprint(self):
        response = MagicMock()
        response.code = 200
        response.read.return_value = b"<html>VPN login password</html>"
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(vpn_probe, "build_opener", return_value=opener):
            fingerprints, observations, errors = vpn_probe.check_https_pages(
                "vpn.example", 443, 1, MagicMock()
            )
        self.assertEqual(fingerprints, [])
        self.assertEqual(len(observations), len(vpn_probe.VPN_PAGE_SIGNATURES))
        self.assertEqual(errors, [])
        self.assertEqual(opener.open.call_count, len(vpn_probe.VPN_PAGE_SIGNATURES))
        response.read.assert_called_with(vpn_probe.MAX_BODY_BYTES)

    def test_http_vendor_fingerprint_requires_vendor_marker(self):
        def open_request(request, timeout):
            response = MagicMock()
            response.code = 200
            response.read.return_value = (
                b"<html>Fortinet FortiGate</html>"
                if "/remote/login" in request.full_url
                else b"<html>generic login</html>"
            )
            return response

        opener = MagicMock()
        opener.open.side_effect = open_request
        with patch.object(vpn_probe, "build_opener", return_value=opener):
            fingerprints, observations, errors = vpn_probe.check_https_pages(
                "vpn.example", 443, 1, MagicMock()
            )
        self.assertEqual(errors, [])
        self.assertEqual(len(observations), len(vpn_probe.VPN_PAGE_SIGNATURES))
        self.assertEqual([entry["vendor"] for entry in fingerprints], ["fortinet"])
        self.assertIn("fortinet", fingerprints[0]["evidence"])

    def test_http_errors_are_returned_explicitly(self):
        opener = MagicMock()
        opener.open.side_effect = URLError("certificate verify failed")
        with patch.object(vpn_probe, "build_opener", return_value=opener):
            fingerprints, observations, errors = vpn_probe.check_https_pages(
                "vpn.example", 443, 1, MagicMock()
            )
        self.assertEqual(fingerprints, [])
        self.assertEqual(observations, [])
        self.assertEqual(len(errors), len(vpn_probe.VPN_PAGE_SIGNATURES))
        self.assertIn("certificate verify failed", errors[0]["error"])

    def test_http_server_errors_include_status_and_error(self):
        opener = MagicMock()
        opener.open.side_effect = lambda *args, **kwargs: HTTPError(
            "https://vpn.example/remote/login", 503, "Unavailable", {}, BytesIO(b"")
        )
        with patch.object(vpn_probe, "build_opener", return_value=opener):
            fingerprints, observations, errors = vpn_probe.check_https_pages(
                "vpn.example", 443, 1, MagicMock()
            )
        self.assertEqual(fingerprints, [])
        self.assertTrue(all(item["status"] == 503 for item in observations))
        self.assertEqual(len(errors), len(vpn_probe.VPN_PAGE_SIGNATURES))
        self.assertEqual(errors[0]["error"], "HTTP status 503")

    def test_external_redirect_is_blocked(self):
        handler = vpn_probe.SameOriginRedirectHandler("vpn.example", 443, MagicMock())
        with self.assertRaises(URLError):
            handler.redirect_request(
                MagicMock(),
                MagicMock(),
                302,
                "Found",
                {},
                "https://other.example/login",
            )


if __name__ == "__main__":
    unittest.main()
