"""Tests for credential exposure and attack path modelling."""
import pytest

from app.breach import hash_password, parse_range_response
from app.graph import build_attack_graph, _sev_from_cvss


# ---- k-anonymity ---------------------------------------------------------

def test_sha1_split_is_five_characters():
    """The 5-char prefix is what creates the anonymity set. Change it and you
    change the privacy guarantee — 6 chars means far smaller buckets."""
    prefix, suffix = hash_password("password123")
    assert len(prefix) == 5
    assert len(prefix) + len(suffix) == 40  # SHA-1 hex is always 40 chars


def test_known_password_hash_is_stable():
    """'password' has a well-known SHA-1. If this breaks, hashing changed."""
    prefix, suffix = hash_password("password")
    assert prefix + suffix == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_hash_is_uppercase():
    """The API returns uppercase hex. Case mismatch means every lookup
    silently misses — a false 'not breached' for every password."""
    prefix, suffix = hash_password("test")
    assert prefix.isupper()
    assert suffix.isupper()


def test_parse_range_finds_matching_suffix():
    body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\nAAAA:1"
    _, suffix = hash_password("password")
    assert parse_range_response(body, suffix) == 12345


def test_parse_range_returns_zero_when_absent():
    body = "0000000000000000000000000000000000A:5\nBBBB:2"
    assert parse_range_response(body, "FFFFFFFF") == 0


def test_parse_range_is_case_insensitive():
    body = "1e4c9b93f3f0682250b6cf8331b7ee68fd8:99"
    _, suffix = hash_password("password")
    assert parse_range_response(body, suffix) == 99


def test_parse_range_survives_malformed_lines():
    """The response is plain text from a third party. Never assume it's clean."""
    body = "garbage-no-colon\n\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:7\nX:notanumber"
    _, suffix = hash_password("password")
    assert parse_range_response(body, suffix) == 7


# ---- attack graph --------------------------------------------------------

def _base_recon() -> dict:
    return {
        "domain": "acme.com",
        "subdomains": ["acme.com", "db.acme.com"],
        "dns_records": {"db.acme.com": {"A": ["10.0.0.9"]}},
        "ips": ["10.0.0.9"],
        "open_ports": [{"host": "10.0.0.9", "port": 6379, "service": "redis"}],
        "cve_correlations": [],
    }


def test_graph_roots_at_internet():
    """Every external attack path must start from the internet node —
    that's what makes it an *external* attack surface model."""
    g = build_attack_graph(_base_recon())
    assert any(n.id == "internet" for n in g.nodes)


def test_exposed_redis_produces_path_to_impact():
    g = build_attack_graph(_base_recon())
    assert g.paths, "expected at least one internet -> impact path"
    assert g.paths[0].nodes[0] == "internet"
    assert any("impact" in n for n in g.paths[0].nodes)


def test_paths_are_deduplicated():
    """Parallel edges can produce identical node sequences. Reporting the same
    path twice inflates perceived risk, which is its own inaccuracy."""
    recon = _base_recon()
    recon["cve_correlations"] = [{
        "product": "nginx", "version": "1.18.0", "error": None,
        "cves": [{"cve_id": "CVE-2021-23017", "cvss_score": 7.7, "severity": "high"}],
    }]
    g = build_attack_graph(recon)
    sequences = [tuple(p.nodes) for p in g.paths]
    assert len(sequences) == len(set(sequences))


def test_graph_respects_node_cap():
    """A domain with thousands of subdomains must not render a hairball.
    A visualization nobody can read has negative value."""
    recon = _base_recon()
    recon["subdomains"] = [f"h{i}.acme.com" for i in range(500)]
    g = build_attack_graph(recon, max_nodes=40)
    assert len(g.nodes) <= 40


def test_breach_creates_independent_entry_vector():
    """Credential exposure bypasses the network path entirely — which is
    precisely why it's so often the real initial access vector."""
    breaches = {"breaches": [{"name": "Adobe"}], "total_accounts_exposed": 152_445_165}
    g = build_attack_graph(_base_recon(), breaches)
    assert any(n.kind == "exposure" for n in g.nodes)
    assert any("Account takeover" in n.label for n in g.nodes)


def test_low_severity_cves_excluded_from_graph():
    """Only path-relevant CVEs belong in the graph. Everything else is noise
    that makes the important routes harder to see."""
    recon = _base_recon()
    recon["cve_correlations"] = [{
        "product": "nginx", "version": "1.0", "error": None,
        "cves": [{"cve_id": "CVE-2020-1", "cvss_score": 2.0, "severity": "low"}],
    }]
    g = build_attack_graph(recon)
    assert not any(n.kind == "vuln" for n in g.nodes)


def test_correlation_error_does_not_break_graph():
    recon = _base_recon()
    recon["cve_correlations"] = [{"product": "nginx", "version": "1.0",
                                  "error": "NVD unreachable", "cves": []}]
    g = build_attack_graph(recon)  # must not raise
    assert g.nodes


def test_graph_has_no_cycles_in_paths():
    """The cycle guard must hold — an infinite path is a hang, not a finding."""
    g = build_attack_graph(_base_recon())
    for p in g.paths:
        assert len(p.nodes) == len(set(p.nodes))


@pytest.mark.parametrize("cvss,expected", [
    (9.8, "critical"), (7.0, "high"), (5.5, "medium"), (1.0, "low"), (None, "unknown"),
])
def test_cvss_severity_mapping(cvss, expected):
    assert _sev_from_cvss(cvss) == expected
