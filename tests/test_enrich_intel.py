import httpx
import pytest

from exposureintel.enrich import Cache, Vulnerability, enrich_vulnerabilities, epss, http

KEV_FEED = {
    "title": "Fake KEV catalog",
    "catalogVersion": "2099.01.01",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2099-0001",
            "dateAdded": "2022-01-01",
            "dueDate": "2022-01-22",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2099-9999",
            "dateAdded": "2023-03-03",
            "dueDate": "2023-03-24",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}
EPSS_DATA = {
    "CVE-2099-0001": {
        "cve": "CVE-2099-0001",
        "epss": "0.970000000",
        "percentile": "0.999000000",
        "date": "2099-01-01",
    },
    "CVE-2099-0002": {
        "cve": "CVE-2099-0002",
        "epss": "0.010000000",
        "percentile": "0.300000000",
        "date": "2099-01-01",
    },
}


def vuln(vuln_id: str, *aliases: str) -> Vulnerability:
    return Vulnerability(vuln_id, tuple(aliases), "", (), None, (), None, None)


A = vuln("GHSA-test-a", "CVE-2099-0001")  # in KEV, high EPSS
B = vuln("GHSA-test-b", "CVE-2099-0002")  # not in KEV, low EPSS
C = vuln("GHSA-test-c")  # no CVE alias


class FakeIntel:
    """Pretends to be both cisa.gov and api.first.org."""

    def __init__(self, kev_status: int = 200, epss_status: int = 200):
        self.kev_status = kev_status
        self.epss_status = epss_status
        self.hosts: list[str] = []

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handle))

    def count(self, host: str) -> int:
        return self.hosts.count(host)

    def handle(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        self.hosts.append(host)
        if host == "www.cisa.gov":
            if self.kev_status != 200:
                return httpx.Response(self.kev_status)
            return httpx.Response(200, json=KEV_FEED)
        if host == "api.first.org":
            if self.epss_status != 200:
                return httpx.Response(self.epss_status)
            asked = request.url.params["cve"].split(",")
            data = [EPSS_DATA[cve] for cve in asked if cve in EPSS_DATA]
            return httpx.Response(200, json={"status": "OK", "total": len(data), "data": data})
        return httpx.Response(404)


@pytest.fixture(autouse=True)
def no_kev_override(monkeypatch):
    monkeypatch.delenv("EXPOSUREINTEL_KEV_URL", raising=False)


@pytest.fixture
def fast_retries(monkeypatch):
    monkeypatch.setattr(http.time, "sleep", lambda seconds: None)


@pytest.fixture
def cache():
    with Cache(":memory:") as c:
        yield c


def test_kev_and_epss_attached(cache):
    result = enrich_vulnerabilities([A, B, C], cache, client=FakeIntel().client())
    a, b, c = (result.intel[v.id] for v in (A, B, C))
    assert a.in_kev is True
    assert a.kev_date_added == "2022-01-01"
    assert a.kev_ransomware is True
    assert a.epss == pytest.approx(0.97)
    assert a.epss_percentile == pytest.approx(0.999)
    assert b.in_kev is False
    assert b.epss == pytest.approx(0.01)
    assert c.in_kev is None
    assert c.epss is None
    assert result.warnings == []


def test_second_run_uses_cache(cache):
    enrich_vulnerabilities([A, B], cache, client=FakeIntel().client())
    second = FakeIntel()
    result = enrich_vulnerabilities([A, B], cache, client=second.client())
    assert second.hosts == []
    assert result.intel[A.id].in_kev is True


def test_offline_without_cache(cache):
    result = enrich_vulnerabilities([A], cache, offline=True)
    intel = result.intel[A.id]
    assert intel.in_kev is None
    assert intel.epss is None
    assert any("KEV" in w for w in result.warnings)
    assert any("EPSS" in w for w in result.warnings)


def test_offline_with_cache(cache):
    enrich_vulnerabilities([A], cache, client=FakeIntel().client())
    result = enrich_vulnerabilities([A], cache, offline=True)
    assert result.intel[A.id].in_kev is True
    assert result.intel[A.id].epss == pytest.approx(0.97)
    assert result.warnings == []


def test_kev_outage_does_not_abort(cache, fast_retries):
    result = enrich_vulnerabilities([A], cache, client=FakeIntel(kev_status=500).client())
    assert result.intel[A.id].in_kev is None
    assert result.intel[A.id].epss == pytest.approx(0.97)
    assert any("KEV" in w for w in result.warnings)


def test_epss_outage_does_not_abort(cache, fast_retries):
    result = enrich_vulnerabilities([A], cache, client=FakeIntel(epss_status=503).client())
    assert result.intel[A.id].in_kev is True
    assert result.intel[A.id].epss is None
    assert any("EPSS" in w for w in result.warnings)


def test_stale_kev_used_when_refresh_fails(cache, fast_retries):
    enrich_vulnerabilities([A], cache, client=FakeIntel().client())
    broken = FakeIntel(kev_status=500)
    result = enrich_vulnerabilities([A], cache, client=broken.client(), refresh=True)
    assert result.intel[A.id].in_kev is True
    assert any("older cached" in w for w in result.warnings)


def test_multiple_cves_are_combined(cache):
    d = vuln("GHSA-test-d", "CVE-2099-0001", "CVE-2099-0002")
    result = enrich_vulnerabilities([d], cache, client=FakeIntel().client())
    intel = result.intel[d.id]
    assert intel.cves == ("CVE-2099-0001", "CVE-2099-0002")
    assert intel.in_kev is True
    assert intel.epss == pytest.approx(0.97)


def test_epss_requests_are_chunked(cache, monkeypatch):
    monkeypatch.setattr(epss, "CHUNK", 2)
    vulns = [vuln(f"GHSA-{i}", f"CVE-2099-20{i}") for i in range(5)]
    fake = FakeIntel()
    enrich_vulnerabilities(vulns, cache, client=fake.client())
    assert fake.count("api.first.org") == 3
    assert fake.count("www.cisa.gov") == 1
