"""
Test suite. Run with: pytest -q

WHAT WE TEST AND WHY
--------------------
We test the PURE logic — parsing, CPE construction, scoring — not the network
calls. Two reasons:

1. Tests that hit crt.sh or NVD are not tests, they're monitoring. They fail
   when a third party has a bad day, and a test suite that cries wolf gets
   ignored.
2. The pure logic is where the security-relevant bugs live. A scoring bug
   silently under-reports risk to a customer. A parsing bug creates false
   positives. Those are the things worth locking down.

The single most important test here is `test_scoring_is_deterministic`. If the
risk score isn't reproducible, the entire product is indefensible.
"""
import pytest

from app.cve import (
    parse_fingerprint, build_cpe, _severity_from_score, _extract_cvss, TTLCache,
)
from app.recon import _is_valid_hostname
from app.scoring import score_target, _band


# ---- fingerprint parsing -------------------------------------------------

@pytest.mark.parametrize("banner,expected", [
    ("nginx/1.18.0", ("nginx", "1.18.0")),
    ("Apache/2.4.41 (Ubuntu)", ("apache", "2.4.41")),
    ("OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", ("openssh", "8.2p1")),
    ("PHP/7.4.3", ("php", "7.4.3")),
])
def test_parse_fingerprint_extracts_version(banner, expected):
    assert parse_fingerprint(banner) == expected


@pytest.mark.parametrize("banner", ["nginx", "cloudflare", "", "Server", None])
def test_parse_fingerprint_refuses_without_version(banner):
    """No version means no correlation. Matching every nginx CVE ever filed
    is noise, and false positives destroy trust faster than missed findings."""
    assert parse_fingerprint(banner) is None


# ---- CPE construction ----------------------------------------------------

def test_build_cpe_uses_correct_vendor():
    # nginx is owned by F5 in NVD's vocabulary, not "nginx". Getting this
    # wrong silently returns zero CVEs — a dangerous false negative.
    assert build_cpe("nginx", "1.18.0") == "cpe:2.3:a:f5:nginx:1.18.0"
    assert build_cpe("apache", "2.4.41") == "cpe:2.3:a:apache:http_server:2.4.41"


def test_build_cpe_returns_none_for_unknown_vendor():
    assert build_cpe("some-unknown-daemon", "1.0") is None


# ---- CVSS handling -------------------------------------------------------

@pytest.mark.parametrize("score,expected", [
    (9.8, "critical"), (9.0, "critical"),
    (7.5, "high"), (7.0, "high"),
    (5.0, "medium"), (4.0, "medium"),
    (2.1, "low"), (None, "unknown"),
])
def test_severity_from_score_boundaries(score, expected):
    assert _severity_from_score(score) == expected


def test_extract_cvss_prefers_v31_over_v2():
    """Older CVEs carry both v2 and v3 metrics. Always prefer the newer,
    more accurate scoring system."""
    cve = {"metrics": {
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}],
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
    }}
    score, severity = _extract_cvss(cve)
    assert score == 9.8
    assert severity == "critical"


# ---- hostname validation -------------------------------------------------

@pytest.mark.parametrize("name,valid", [
    ("example.com", True),
    ("dev.example.com", True),
    ("as207960 test intermediate - example.com", False),  # the real CT-log bug
    ("user@example.com", False),
    ("not-our-domain.org", False),
    ("", False),
])
def test_hostname_validation(name, valid):
    assert _is_valid_hostname(name, "example.com") is valid


# ---- scoring -------------------------------------------------------------

def _recon_with_port(port: int) -> dict:
    return {"open_ports": [{"host": "1.2.3.4", "port": port, "state": "open"}],
            "certificates": [], "subdomains": [], "cve_correlations": []}


def test_exposed_redis_scores_critical():
    r = score_target(_recon_with_port(6379))
    assert r["score"] == 30
    assert any(f["severity"] == "critical" for f in r["findings"])


def test_clean_target_scores_zero():
    r = score_target({"open_ports": [], "certificates": [],
                      "subdomains": [], "cve_correlations": []})
    assert r["score"] == 0
    assert r["severity"] == "informational"


def test_scoring_is_deterministic():
    """THE most important test in the suite. A risk score you cannot
    reproduce is a risk score you cannot defend to an auditor."""
    recon = _recon_with_port(3306)
    scores = {score_target(recon)["score"] for _ in range(20)}
    assert len(scores) == 1


def test_cve_contribution_is_capped():
    """50 medium CVEs must not outrank an exposed unauthenticated database.
    Attack surface risk is about exploitability in context, not CVE count."""
    recon = {"open_ports": [], "certificates": [], "subdomains": [],
             "cve_correlations": [{
                 "product": "nginx", "version": "1.0", "cpe": "x", "error": None,
                 "cves": [{"cve_id": f"CVE-2020-{i}", "cvss_score": 9.9,
                           "severity": "critical"} for i in range(50)],
             }]}
    assert score_target(recon)["score"] == 45  # the cap, not 600


def test_correlation_error_surfaces_as_finding():
    """'Couldn't check' must never render as 'nothing found'."""
    recon = {"open_ports": [], "certificates": [], "subdomains": [],
             "cve_correlations": [{"product": "nginx", "version": "1.0",
                                   "cpe": "", "cves": [],
                                   "error": "NVD unreachable"}]}
    r = score_target(recon)
    assert any("unavailable" in f["title"].lower() for f in r["findings"])


@pytest.mark.parametrize("score,band", [
    (0, "informational"), (5, "low"), (25, "medium"),
    (50, "high"), (85, "critical"),
])
def test_severity_bands(score, band):
    assert _band(score) == band


# ---- cache ---------------------------------------------------------------

def test_ttl_cache_expires():
    c = TTLCache(ttl=-1)  # already expired
    c.set("k", "v")
    assert c.get("k") is None


def test_ttl_cache_returns_fresh_value():
    c = TTLCache(ttl=60)
    c.set("k", "v")
    assert c.get("k") == "v"
