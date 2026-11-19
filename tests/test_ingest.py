from pathlib import Path

import pytest

from exposureintel.ingest import IngestError, load_components

DATA = Path(__file__).parent / "data"


def pairs(components):
    return {(c.name, c.version) for c in components}


def test_requirements_pinned_only():
    comps = load_components(DATA / "sample_requirements.txt")
    assert pairs(comps) == {("requests", "2.19.0"), ("flask", "1.0"), ("pyyaml", "5.3")}
    assert all(c.ecosystem == "PyPI" for c in comps)


def test_cyclonedx_nested_and_unsupported():
    comps = load_components(DATA / "sample_cyclonedx.json")
    assert pairs(comps) == {
        ("requests", "2.19.0"),
        ("lodash", "4.17.15"),
        ("@babel/core", "7.0.0"),
        ("urllib3", "1.24.1"),
    }  # the maven package is skipped
    babel = next(c for c in comps if c.name == "@babel/core")
    assert babel.purl == "pkg:npm/%40babel/core@7.0.0"


def test_spdx_uses_purl_refs():
    comps = load_components(DATA / "sample_spdx.json")
    assert pairs(comps) == {("requests", "2.19.0")}


def test_package_lock_direct_flags():
    comps = load_components(DATA / "sample_package_lock.json")
    assert len(comps) == 4
    by_key = {(c.name, c.version): c for c in comps}
    assert by_key[("lodash", "4.17.15")].direct is True
    assert by_key[("minimist", "1.2.0")].direct is False
    assert by_key[("minimist", "0.0.8")].direct is False


def test_missing_file():
    with pytest.raises(IngestError):
        load_components(DATA / "nope.json")


def test_invalid_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(IngestError):
        load_components(bad)


def test_unrecognized_json(tmp_path):
    odd = tmp_path / "odd.json"
    odd.write_text('{"a": 1}')
    with pytest.raises(IngestError):
        load_components(odd)


def test_old_lockfile_rejected(tmp_path):
    old = tmp_path / "package-lock.json"
    old.write_text('{"lockfileVersion": 1, "dependencies": {}}')
    with pytest.raises(IngestError):
        load_components(old)
