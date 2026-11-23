# SPDX-License-Identifier: MIT
"""Offline regression tests for the static site audit and its ON/OFF behavior."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from simplebrush_site_audit import FLAG, audit_site, cli, flag_enabled  # noqa: E402


PAGE_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Simple Brush | {label}</title>
<link rel="stylesheet" href="style.css"></head>
<body><header><nav aria-label="Primary"><a href="index.html">Home</a>
<a href="support.html">Support</a><a href="privacy-policy.html#privacy">Privacy</a>
<a href="terms-of-use.html">Terms</a></nav></header>
<main id="main"><h1 id="{slug}">{label}</h1>{body}</main>
<footer><p>Local support information.</p></footer></body></html>
"""


def _write(root: Path, name: str, text: str) -> None:
    dest = root / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")


@pytest.fixture
def site(tmp_path: Path) -> Path:
    root = tmp_path / "site"
    root.mkdir()
    cases = {
        "index.html": ("Home", "home", '<p>Product guidance.</p><img src="art/mark.svg" alt="Mark"><img srcset="art/mark.svg 1x, art/mark-2.svg 2x" src="art/mark.svg" alt="Decoration">'),
        "privacy-policy.html": ("Privacy", "privacy", "<p>We do not use analytics. We do not track visitors.</p>"),
        "support.html": ("Support", "support", '<p>Read the <a href="terms-of-use.html#terms">terms section</a>.</p>'),
        "terms-of-use.html": ("Terms", "terms", "<p>Local conditions of use.</p>"),
    }
    for name, (label, slug, body) in cases.items():
        _write(root, name, PAGE_TEMPLATE.format(label=label, slug=slug, body=body))
    _write(root, "style.css", "body{font-family:sans-serif} .brand{background:url('art/mark.svg')}")
    _write(root, "art/mark.svg", '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"></svg>')
    _write(root, "art/mark-2.svg", '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 2 2"></svg>')
    return root


def _append(root: Path, name: str, html: str, before: str = "</main>") -> None:
    path = root / name
    path.write_text(path.read_text(encoding="utf-8").replace(before, html + before), encoding="utf-8")


def _replace(root: Path, name: str, old: str, new: str) -> None:
    path = root / name
    data = path.read_text(encoding="utf-8")
    assert old in data
    path.write_text(data.replace(old, new), encoding="utf-8")


def _rules(root: Path) -> set[str]:
    return {f.rule for f in audit_site(root, environ={}).findings if f.severity == "ERROR"}


def _snapshot(root: Path) -> dict[str, str]:
    return {
        item.relative_to(root).as_posix(): hashlib.sha256(item.read_bytes()).hexdigest()
        for item in root.rglob("*") if item.is_file()
    }


def test_clean_site_passes_and_is_read_only(site: Path) -> None:
    old = _snapshot(site)
    result = audit_site(site, environ={})
    assert result.ok, result.findings
    assert result.html_files == 4
    assert result.css_files == 1
    assert result.local_references >= 10
    assert result.external_navigation == 0
    assert result.as_json()["all"] is True
    assert _snapshot(site) == old


def test_flag_on_by_default_and_explicit_off_only() -> None:
    assert flag_enabled({})
    assert flag_enabled({FLAG: ""})
    assert flag_enabled({FLAG: "ON"})
    assert flag_enabled({FLAG: "unexpected"})
    for value in ("0", "false", "OFF", " No "):
        assert not flag_enabled({FLAG: value})


def test_kill_switch_off_returns_noop_even_for_invalid_root(site: Path, tmp_path: Path) -> None:
    old = _snapshot(site)
    _append(site, "index.html", '<script src="https://metrics.invalid/collect.js"></script>')
    after_change = _snapshot(site)
    result = audit_site(site, environ={FLAG: "OFF"})
    assert result.disabled and result.ok and result.html_files == 0
    assert result.findings == []
    assert _snapshot(site) == after_change
    assert old != after_change
    assert audit_site(tmp_path / "missing", environ={FLAG: "0"}).ok


def test_required_page_missing(site: Path) -> None:
    (site / "support.html").unlink()
    assert "REQUIRED_PAGE_MISSING" in _rules(site)


def test_broken_local_html_link(site: Path) -> None:
    _append(site, "index.html", '<a href="missing.html">Missing</a>')
    assert "BROKEN_LOCAL_LINK" in _rules(site)


def test_broken_fragment(site: Path) -> None:
    _append(site, "index.html", '<a href="support.html#not-present">Section</a>')
    assert "BROKEN_FRAGMENT" in _rules(site)


def test_fragment_percent_decoding_and_root_relative_path(site: Path) -> None:
    _append(site, "index.html", '<a href="/support.html#support">Section</a>')
    _append(site, "index.html", '<a href="support.html#supp%6frt">Section 2</a>')
    assert audit_site(site, environ={}).ok


def test_directory_index_resolution(site: Path) -> None:
    _write(site, "notes/index.html", PAGE_TEMPLATE.format(label="Notes", slug="notes", body="<p>Notes.</p>").replace('href="style.css"', 'href="../style.css"').replace('href="index.html"', 'href="../index.html"').replace('href="support.html"', 'href="../support.html"').replace('href="privacy-policy.html#privacy"', 'href="../privacy-policy.html#privacy"').replace('href="terms-of-use.html"', 'href="../terms-of-use.html"'))
    _append(site, "index.html", '<a href="notes/">Notes</a>')
    assert audit_site(site, environ={}).ok


def test_broken_css_asset(site: Path) -> None:
    _write(site, "style.css", 'body{background-image:url("missing.png")}')
    assert "BROKEN_LOCAL_LINK" in _rules(site)


def test_css_comment_does_not_generate_reference(site: Path) -> None:
    _write(site, "style.css", "/* background:url('not-real.png'); */ body{margin:0}")
    assert audit_site(site, environ={}).ok


def test_css_import_literal_checked(site: Path) -> None:
    _write(site, "style.css", "@import 'extra.css';\nbody{margin:0}")
    assert "BROKEN_LOCAL_LINK" in _rules(site)
    _write(site, "extra.css", "p{margin:0}")
    assert audit_site(site, environ={}).ok


def test_css_import_function_remote_rejected(site: Path) -> None:
    _write(site, "style.css", '@import url("https://metrics.invalid/theme.css");')
    assert "REMOTE_RESOURCE" in _rules(site)


def test_css_unparseable_import(site: Path) -> None:
    _write(site, "style.css", "@import maybe-a-url;")
    assert "UNPARSEABLE_IMPORT" in _rules(site)


def test_style_attribute_remote_resource(site: Path) -> None:
    _append(site, "index.html", '<p style="background:url(https://metrics.invalid/track.png)">Text</p>')
    assert "REMOTE_RESOURCE" in _rules(site)


def test_inline_style_block_local_missing_resource(site: Path) -> None:
    _append(site, "index.html", '<style>.decor {background:url("lost.svg")}</style>')
    assert "BROKEN_LOCAL_LINK" in _rules(site)


def test_css_plain_string_image_set_is_rejected(site: Path) -> None:
    _write(site, "style.css", 'body{background:image-set("https://metrics.invalid/a.png" 1x)}')
    assert "UNSUPPORTED_CSS_RESOURCE" in _rules(site)


def test_svg_external_image_rejected(site: Path) -> None:
    _append(site, "index.html", '<svg><image href="https://metrics.invalid/a.svg"></image></svg>')
    assert "REMOTE_RESOURCE" in _rules(site)


def test_svg_local_fragment_works(site: Path) -> None:
    _append(site, "index.html", '<svg><symbol id="symbolA"></symbol><use href="#symbolA"></use></svg>')
    assert audit_site(site, environ={}).ok


def test_svg_missing_fragment_rejected(site: Path) -> None:
    _append(site, "index.html", '<svg><use href="#absent"></use></svg>')
    assert "BROKEN_FRAGMENT" in _rules(site)


def test_hyperlink_ping_rejected(site: Path) -> None:
    _append(site, "index.html", '<a href="support.html" ping="https://metrics.invalid/post">Support</a>')
    assert "LINK_PING_NOT_ALLOWED" in _rules(site)


def test_meta_cookie_directive_rejected(site: Path) -> None:
    _append(site, "index.html", '<meta http-equiv="set-cookie" content="x=y">')
    assert "META_COOKIE_NOT_ALLOWED" in _rules(site)


def test_privacy_coordinated_no_analytics_or_tracking(site: Path) -> None:
    _replace(site, "privacy-policy.html", "We do not use analytics. We do not track visitors.", "No analytics or tracking tools are used.")
    assert audit_site(site, environ={}).ok


def test_remote_active_resources_rejected(site: Path) -> None:
    _append(site, "index.html", '<img src="https://metrics.invalid/pixel.png" alt="">')
    assert "REMOTE_RESOURCE" in _rules(site)


def test_external_navigation_is_unverified_not_broken(site: Path) -> None:
    _append(site, "index.html", '<a href="https://outside.invalid/information">External information</a>')
    result = audit_site(site, environ={})
    assert result.ok
    assert result.external_navigation == 1


@pytest.mark.parametrize("query", ["utm_source=notice", "click_id=123", "gclid=1"])
def test_tracking_query_parameter_rejected(site: Path, query: str) -> None:
    _append(site, "index.html", f'<a href="support.html?{query}">Support link</a>')
    assert "TRACKING_PARAMETER" in _rules(site)


def test_tracking_resource_path_rejected(site: Path) -> None:
    _write(site, "pixel.gif", "sample")
    _append(site, "index.html", '<img src="pixel.gif" alt="">')
    assert "TRACKING_ENDPOINT" in _rules(site)


@pytest.mark.parametrize("html,rule", [
    ('<script>void 0</script>', "SCRIPT_NOT_ALLOWED"),
    ('<img src="art/mark.svg" alt="" onload="run()">', "EVENT_HANDLER_NOT_ALLOWED"),
    ('<iframe src="local.html"></iframe>', "EMBED_NOT_ALLOWED"),
    ('<base href="/">', "BASE_URL_NOT_ALLOWED"),
    ('<img src="data:image/png;base64,aaaa" alt="">', "UNSAFE_SCHEME"),
    ('<a href="javascript:run()">Go</a>', "UNSAFE_SCHEME"),
    ('<img src="" alt="">', "EMPTY_RESOURCE"),
    ('<img src="missing.png">', "MISSING_IMAGE_ALT"),
    ('<a href="support.html"></a>', "UNNAMED_LINK"),
    ('<p id="main">Duplicate id</p>', "DUPLICATE_ID"),
    ('<meta http-equiv="refresh" content="0;url=/">', "META_REFRESH_NOT_ALLOWED"),
])
def test_html_policy_and_semantics(site: Path, html: str, rule: str) -> None:
    _append(site, "index.html", html)
    assert rule in _rules(site)


@pytest.mark.parametrize("old,new,rule", [
    ('<html lang="en">', "<html>", "MISSING_LANG"),
    ('<title>Simple Brush | Home</title>', "<title></title>", "PAGE_TITLE"),
    ('<header>', '<div>', "LANDMARK_COUNT"),
    ('</header>', '</div>', "UNCLOSED_LANDMARK"),
    ('<nav aria-label="Primary">', '<div>', "LANDMARK_MISSING"),
    ('</nav>', '</div>', "UNCLOSED_LANDMARK"),
    ('<main id="main">', '<div id="main">', "LANDMARK_COUNT"),
    ('</main>', '</div>', "UNCLOSED_LANDMARK"),
    ('<h1 id="home">Home</h1>', '<h2 id="home">Home</h2>', "LANDMARK_COUNT"),
    ('<footer>', '<div>', "LANDMARK_COUNT"),
    ('</footer>', '</div>', "UNCLOSED_LANDMARK"),
])
def test_landmark_contract(site: Path, old: str, new: str, rule: str) -> None:
    _replace(site, "index.html", old, new)
    assert rule in _rules(site)


def test_multiple_navs_require_labels(site: Path) -> None:
    _append(site, "index.html", '<nav><a href="index.html">Home</a></nav>')
    assert "NAV_LABEL_MISSING" in _rules(site)


def test_privacy_missing_claim(site: Path) -> None:
    _replace(site, "privacy-policy.html", "We do not use analytics. We do not track visitors.", "We provide a privacy policy.")
    result = audit_site(site, environ={})
    assert sum(f.rule == "PRIVACY_CLAIM_MISSING" for f in result.findings) == 2


def test_privacy_partially_missing_claim(site: Path) -> None:
    _replace(site, "privacy-policy.html", "We do not use analytics. We do not track visitors.", "We do not use analytics.")
    assert "PRIVACY_CLAIM_MISSING" in _rules(site)


def test_privacy_positive_contradiction(site: Path) -> None:
    _append(site, "privacy-policy.html", "<p>We use analytics.</p>")
    assert "PRIVACY_CLAIM_CONTRADICTION" in _rules(site)


def test_path_escape_rejected(site: Path) -> None:
    _append(site, "index.html", '<a href="../../outside.html">Outside</a>')
    assert "PATH_ESCAPES_SITE" in _rules(site)


def test_symlink_escape_rejected(site: Path, tmp_path: Path) -> None:
    other = tmp_path / "foreign.css"
    other.write_text("h1{margin:0}", encoding="utf-8")
    (site / "foreign.css").symlink_to(other)
    _append(site, "index.html", '<link rel="stylesheet" href="foreign.css">')
    assert "FILE_OUTSIDE_SITE" in _rules(site) or "PATH_ESCAPES_SITE" in _rules(site)


def test_missing_site_root(site: Path) -> None:
    result = audit_site(site / "does-not-exist", environ={})
    assert not result.ok
    assert "SITE_ROOT_MISSING" in {f.rule for f in result.findings}


def test_invalid_utf8_file(site: Path) -> None:
    (site / "style.css").write_bytes(b"\xff\x00")
    assert "FILE_READ_ERROR" in _rules(site)


def test_cli_json_status_and_stable_shape(site: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(FLAG, raising=False)
    assert cli(["--site-root", str(site), "--format", "json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["all"] is True
    assert output["disabled"] is False
    assert output["findings"] == []
    assert output["external_navigation_unverified"] == 0


def test_cli_exit_status_on_failure(site: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(FLAG, raising=False)
    _append(site, "index.html", '<a href="missing.html">Missing</a>')
    assert cli(["--site-root", str(site)]) == 1
    text = capsys.readouterr().out
    assert "ERROR|BROKEN_LOCAL_LINK" in text and "ALL=false" in text


def test_cli_off_status_and_output(site: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(FLAG, "0")
    assert cli(["--site-root", str(site)]) == 0
    output = capsys.readouterr().out
    assert "DISABLED" in output and "ALL=true" in output


def test_actual_command_in_fresh_interpreter(site: Path) -> None:
    script = Path(__file__).resolve().parents[1] / "tools" / "simplebrush_site_audit.py"
    cmd = [sys.executable, str(script), "--site-root", str(site)]
    completed = subprocess.run(cmd, text=True, capture_output=True, check=False, timeout=10)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "ALL=true" in completed.stdout


def test_directory_and_files_unchanged_by_audit(site: Path) -> None:
    before = _snapshot(site)
    for i in range(3):
        assert audit_site(site, environ={}).ok
    assert _snapshot(site) == before
