"""Tests for target and port-spec validation."""

from scanner.validator import validate_target, validate_ports


class TestValidateTarget:
    def test_ipv4(self):
        ok, kind = validate_target("192.168.1.1")
        assert ok and kind == "ip"

    def test_ipv6(self):
        ok, kind = validate_target("::1")
        assert ok and kind in ("ip", "cidr")

    def test_hostname(self):
        ok, kind = validate_target("example.com")
        assert ok and kind == "hostname"

    def test_cidr(self):
        ok, kind = validate_target("10.0.0.0/24")
        assert ok and kind == "cidr"

    def test_cidr_too_large_rejected(self):
        ok, _ = validate_target("10.0.0.0/8")
        assert not ok

    def test_empty_rejected(self):
        ok, _ = validate_target("   ")
        assert not ok

    def test_garbage_rejected(self):
        ok, _ = validate_target("not a host!!")
        assert not ok


class TestValidatePorts:
    def test_single(self):
        ok, norm = validate_ports("80")
        assert ok and norm == "80"

    def test_range(self):
        ok, norm = validate_ports("1-1024")
        assert ok and norm == "1-1024"

    def test_list(self):
        ok, norm = validate_ports("80,443,8080")
        assert ok and norm == "80,443,8080"

    def test_all_keyword(self):
        ok, norm = validate_ports("all")
        assert ok and norm == "1-65535"

    def test_out_of_range_rejected(self):
        ok, _ = validate_ports("70000")
        assert not ok

    def test_reversed_range_rejected(self):
        ok, _ = validate_ports("1000-10")
        assert not ok

    def test_non_numeric_rejected(self):
        ok, _ = validate_ports("http")
        assert not ok
