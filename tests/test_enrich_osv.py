import json
from pathlib import Path

import httpx
import pytest

from exposureintel.enrich import Cache, OsvError, find_vulnerabilities, osv
from exposureintel.ingest import Component

RECORD = json.loads((Path(__file__).parent / "data" / "sample_osv_record.json").read_text())
REQ = Component("requests", "2.19.0", "PyPI", "pkg:pypi/requests@2.19.0")
LODASH = Component("lodash", "4.17.15", "npm", "pkg:npm/lodash@4.17.15")


def make_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.osv.dev")


class FakeOsv:
    """Pretends to be OSV.dev: only the 'requests' package is vulnerable."""

    def __init__(self, record=None):
        self.record = record or RECORD
        self.calls: list[str] = []

    def client(self) -> httpx.Client:
        return make_client(self.handle)

    def count(self, path: str) -> int:
        return self.calls.count(path)

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append(path)
        if path == "/v1/querybatch":
            results = []
            for query in json.loads(request.content)["queries"]:
                if query["package"]["name"] == "requests":
                    vuln = {"id": self.record["id"], "modified": self.record["modified"]}
                    results.append({"vulns": [vuln]})
                else:
                    results.append({})
            return httpx.Response(200, json={"results": results})
        if path == f"/v1/vulns/{self.record['id']}":
            return httpx.Response(200, json=self.record)
        return httpx.Response(404)


@pytest.fixture
def cache():
    with Cache(":memory:") as c:
        yield c


def test_finds_and_parses(cache):
    result = find_vulnerabilities([REQ, LODASH], cache, client=FakeOsv().client())
    vuln = result.vulns[REQ.purl][0]
    assert vuln.id == RECORD["id"]
    assert vuln.cve_ids == ("CVE-2018-18074",)
    assert vuln.fixed_versions == ("2.20.0",)  # the npm entry is ignored
    assert vuln.db_severity == "HIGH"
    assert vuln.severity_vectors[0][0] == "CVSS_V3"
    assert result.vulns[LODASH.purl] == []
    assert result.unchecked == []


def test_second_run_uses_cache(cache):
    find_vulnerabilities([REQ, LODASH], cache, client=FakeOsv().client())
    second = FakeOsv()
    result = find_vulnerabilities([REQ, LODASH], cache, client=second.client())
    assert second.calls == []
    assert len(result.vulns[REQ.purl]) == 1


def test_offline_reports_unchecked(cache):
    result = find_vulnerabilities([REQ], cache, offline=True)
    assert result.vulns == {}
    assert result.unchecked == [REQ]


def test_offline_serves_cached_results(cache):
    find_vulnerabilities([REQ], cache, client=FakeOsv().client())
    result = find_vulnerabilities([REQ, LODASH], cache, offline=True)
    assert len(result.vulns[REQ.purl]) == 1
    assert result.unchecked == [LODASH]


def test_pagination_follows_next_page_token(cache):
    second_id = "GHSA-test-page-two"

    def handle(request):
        path = request.url.path
        if path == "/v1/querybatch":
            query = json.loads(request.content)["queries"][0]
            if query.get("page_token") == "tok2":
                vuln = {"id": second_id, "modified": "2024-01-01T00:00:00Z"}
                return httpx.Response(200, json={"results": [{"vulns": [vuln]}]})
            vuln = {"id": RECORD["id"], "modified": RECORD["modified"]}
            page = {"vulns": [vuln], "next_page_token": "tok2"}
            return httpx.Response(200, json={"results": [page]})
        vuln_id = path.rsplit("/", 1)[-1]
        return httpx.Response(200, json={**RECORD, "id": vuln_id, "aliases": []})

    result = find_vulnerabilities([REQ], cache, client=make_client(handle))
    assert {v.id for v in result.vulns[REQ.purl]} == {RECORD["id"], second_id}


def test_batches_are_split(cache, monkeypatch):
    monkeypatch.setattr(osv, "BATCH_SIZE", 2)
    comps = [Component(f"pkg{i}", "1.0", "PyPI", f"pkg:pypi/pkg{i}@1.0") for i in range(5)]
    fake = FakeOsv()
    result = find_vulnerabilities(comps, cache, client=fake.client())
    assert fake.count("/v1/querybatch") == 3
    assert all(v == [] for v in result.vulns.values())


def test_retries_transient_errors(cache, monkeypatch):
    monkeypatch.setattr(osv.time, "sleep", lambda seconds: None)
    fake = FakeOsv()
    failures = {"left": 2}

    def flaky(request):
        if failures["left"] > 0:
            failures["left"] -= 1
            return httpx.Response(503)
        return fake.handle(request)

    result = find_vulnerabilities([REQ], cache, client=make_client(flaky))
    assert len(result.vulns[REQ.purl]) == 1


def test_withdrawn_advisories_are_skipped(cache):
    withdrawn = {**RECORD, "withdrawn": "2024-02-02T00:00:00Z"}
    result = find_vulnerabilities([REQ], cache, client=FakeOsv(withdrawn).client())
    assert result.vulns[REQ.purl] == []


def test_client_error_raises(cache):
    client = make_client(lambda request: httpx.Response(400))
    with pytest.raises(OsvError):
        find_vulnerabilities([REQ], cache, client=client)
