#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only, offline audit of a static HTML/CSS support site.

No network access, dynamic execution, HTML rewriting, or third-party runtime
packages are used. Audit behavior is enabled unless the documented environment
kill switch is explicitly set to an OFF value.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import parse_qsl, unquote, urlsplit

FLAG = "SIMPLEBRUSH_SITE_AUDIT"
OFF_VALUES = frozenset({"0", "false", "off", "no"})
REQUIRED_PAGES = (
    "index.html",
    "privacy-policy.html",
    "support.html",
    "terms-of-use.html",
)
SKIP_DIRS = frozenset({".git", ".venv", "__pycache__", ".pytest_cache", "node_modules", "dist", "build"})
VOID_ELEMENTS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
})
RESOURCE_LINK_RELS = frozenset({
    "stylesheet", "icon", "manifest", "preload", "modulepreload", "prefetch",
    "prerender", "preconnect", "dns-prefetch", "mask-icon",
})
RESOURCE_ATTRIBUTES = {
    "img": ("src", "srcset"), "source": ("src", "srcset"),
    "script": ("src",), "iframe": ("src",), "frame": ("src",),
    "video": ("src", "poster"), "audio": ("src",),
    "track": ("src",), "embed": ("src",), "object": ("data",),
    "input": ("src",), "form": ("action",),
    "image": ("href", "xlink:href"), "use": ("href", "xlink:href"),
    "feimage": ("href", "xlink:href"),
    "body": ("background",), "td": ("background",), "th": ("background",),
}
TRACKING_PARAMETERS = frozenset({
    "gclid", "fbclid", "msclkid", "twclid", "igshid", "yclid",
    "mc_cid", "mc_eid", "_ga", "click_id", "tracking_id",
    "visitor_id", "campaign_id",
})
TRACKING_PATH_RE = re.compile(r"(?:^|[/_.-])(?:pixel|beacon|analytics|tracking|collect)(?:$|[/_.-])", re.I)
CSS_URL_RE = re.compile(r"(?i)(?<![\w-])url\s*\(\s*(?:([\"'])(.*?)\1|([^)]*?))\s*\)", re.S)
CSS_IMPORT_RE = re.compile(r"(?i)@import\s+([\"'])(.*?)\1", re.S)
CSS_IMPORT_ANY_RE = re.compile(r"(?i)@import\b")
CSS_IMAGE_SET_RE = re.compile(r"(?i)\bimage-set\s*\(")
CSS_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
NEGATIVE_ANALYTICS = (
    re.compile(r"\bno\s+(?:(?:third.party|website|visitor|user)\s+){0,2}analytics\b", re.I),
    re.compile(r"\bno\b(?:(?![.!?]).){0,90}\banalytics\b", re.I),
    re.compile(r"\b(?:do not|does not|don't|doesn't|never)\b.{0,120}\b(?:use|run|collect|enable|employ|have|deploy)\b.{0,75}\banalytics\b", re.I),
    re.compile(r"\banalytics\s+(?:is|are)\s+(?:not|never)\s+(?:used|enabled|collected)\b", re.I),
)
NEGATIVE_TRACKING = (
    re.compile(r"\bno\s+(?:(?:visitor|user|website|third.party)\s+){0,2}(?:tracking|trackers)\b", re.I),
    re.compile(r"\bno\b(?:(?![.!?]).){0,90}\b(?:tracking|trackers)\b", re.I),
    re.compile(r"\b(?:do not|does not|don't|doesn't|never)\b.{0,120}\b(?:track|tracking|trackers)\b", re.I),
    re.compile(r"\btracking\s+(?:is|are)\s+(?:not|never)\s+(?:used|enabled|performed)\b", re.I),
)
POSITIVE_ANALYTICS = (
    re.compile(r"\b(?:we|this site|our website)\s+(?:do\s+)?(?:use|run|collect|enable|employ|deploy)\s+(?:(?:third.party|website|visitor)\s+){0,2}analytics\b", re.I),
    re.compile(r"\b(?:we|this site|our website)\s+may\s+(?:use|run|collect|enable)\s+analytics\b", re.I),
)
POSITIVE_TRACKING = (
    re.compile(r"\b(?:we|this site|our website)\s+(?:track|tracks)\s+(?:users|visitors|your|you|activity)\b", re.I),
    re.compile(r"\b(?:we|this site|our website)\s+may\s+track\b", re.I),
)


def flag_enabled(environ: dict[str, str] | None = None) -> bool:
    """ON by default; OFF only on an explicit documented value."""
    env = os.environ if environ is None else environ
    return env.get(FLAG, "on").strip().lower() not in OFF_VALUES


@dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    file: str
    line: int
    detail: str


@dataclass(frozen=True)
class Reference:
    file: str
    line: int
    tag: str
    attribute: str
    url: str
    resource: bool
    fragment_check: bool = False


@dataclass
class Page:
    file: str
    ids: set[str] = field(default_factory=set)
    references: list[Reference] = field(default_factory=list)
    readable_text: list[str] = field(default_factory=list)
    titles: list[str] = field(default_factory=list)
    landmark_count: dict[str, int] = field(default_factory=lambda: {k: 0 for k in ("header", "nav", "main", "footer", "h1")})
    lang: str = ""


@dataclass
class Result:
    root: str
    disabled: bool = False
    html_files: int = 0
    css_files: int = 0
    local_references: int = 0
    external_navigation: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(f.severity == "ERROR" for f in self.findings)

    def as_json(self) -> dict:
        return {
            "all": self.ok,
            "disabled": self.disabled,
            "root": self.root,
            "html_files": self.html_files,
            "css_files": self.css_files,
            "local_references": self.local_references,
            "external_navigation_unverified": self.external_navigation,
            "findings": [asdict(item) for item in self.findings],
        }


def _line(text: str, offset: int, base: int = 1) -> int:
    return base + text.count("\n", 0, offset)


def _uncomment_css(text: str) -> str:
    # Preserve line numbers while suppressing URLs in comments.
    return CSS_COMMENT_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def _css_references(text: str, file: str, base_line: int = 1) -> tuple[list[Reference], list[Finding]]:
    clean = _uncomment_css(text)
    refs: list[Reference] = []
    errors: list[Finding] = []
    for match in CSS_URL_RE.finditer(clean):
        url = match.group(2) if match.group(1) else match.group(3)
        refs.append(Reference(file, _line(clean, match.start(), base_line), "css", "url", url.strip(), True))
    for match in CSS_IMPORT_RE.finditer(clean):
        # Function-form imports already appear in the URL scanner.
        refs.append(Reference(file, _line(clean, match.start(), base_line), "css", "@import", match.group(2).strip(), True))
    # Plain-string image-set candidates can fetch resources without url(...).
    # Fail closed rather than silently accepting a resource we have not parsed.
    for match in CSS_IMAGE_SET_RE.finditer(clean):
        errors.append(Finding("ERROR", "UNSUPPORTED_CSS_RESOURCE", file, _line(clean, match.start(), base_line), "CSS image-set requires manual resource review and is disallowed"))
    for match in CSS_IMPORT_ANY_RE.finditer(clean):
        tail = clean[match.end():]
        if not re.match(r"\s*(?:url\s*\(|[\"'])", tail, re.I):
            errors.append(Finding("ERROR", "UNPARSEABLE_IMPORT", file, _line(clean, match.start(), base_line), "CSS import has an unsupported URL syntax"))
    return refs, errors


def _srcset_urls(value: str) -> list[str]:
    # Strictly reject data schemes during reference evaluation. Standard static
    # srcset candidates use comma separators and optional density descriptors.
    return [part.strip().split()[0] for part in value.split(",") if part.strip()]


class _PageParser(HTMLParser):
    def __init__(self, file: str):
        super().__init__(convert_charrefs=True)
        self.page = Page(file)
        self.findings: list[Finding] = []
        self._title_depth = 0
        self._style_depth = 0
        self._head_depth = 0
        self._script_depth = 0
        self._style_chunks: list[tuple[int, str]] = []
        self._anchor_stack: list[dict[str, object]] = []
        self._landmark_open: list[tuple[str, int]] = []
        self._heading_stack: list[list[str]] = []
        self._nav_labels: list[str] = []
        self._title_buf: list[str] = []
        self._title_nodes = 0

    def _error(self, rule: str, line: int, detail: str) -> None:
        self.findings.append(Finding("ERROR", rule, self.page.file, line, detail))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() not in VOID_ELEMENTS:
            self.handle_endtag(tag)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        lineno = self.getpos()[0]
        a = {key.lower(): (value or "") for key, value in attrs}
        if len(a) != len(attrs):
            self._error("DUPLICATE_ATTRIBUTE", lineno, f"Duplicate attribute in <{tag}>")
        if tag == "html":
            self.page.lang = a.get("lang", "").strip()
        if tag == "head":
            self._head_depth += 1
        if tag == "title":
            self._title_depth += 1
            self._title_nodes += 1
        if tag == "style":
            self._style_depth += 1
        if tag == "script":
            self._script_depth += 1
            self._error("SCRIPT_NOT_ALLOWED", lineno, "Script elements are incompatible with the static zero-tracking policy")
        if tag in ("iframe", "frame", "embed", "object"):
            self._error("EMBED_NOT_ALLOWED", lineno, f"Embedded content <{tag}> is incompatible with the static zero-tracking policy")
        if tag == "base":
            self._error("BASE_URL_NOT_ALLOWED", lineno, "Base URLs change offline link resolution and are not allowed")
        if tag == "meta":
            equiv = a.get("http-equiv", "").lower().strip()
            if equiv == "refresh":
                self._error("META_REFRESH_NOT_ALLOWED", lineno, "Automatic redirects are not allowed")
            if equiv == "set-cookie":
                self._error("META_COOKIE_NOT_ALLOWED", lineno, "HTML cookie directives are incompatible with the zero-tracking policy")
        if tag in self.page.landmark_count:
            self.page.landmark_count[tag] += 1
            self._landmark_open.append((tag, lineno))
            if tag == "nav":
                self._nav_labels.append(a.get("aria-label", "").strip())
            if tag == "h1":
                self._heading_stack.append([])
        item_id = a.get("id")
        if item_id is not None:
            if not item_id.strip():
                self._error("EMPTY_ID", lineno, "An HTML id cannot be blank")
            elif item_id in self.page.ids:
                self._error("DUPLICATE_ID", lineno, f"Duplicate id: {item_id}")
            else:
                self.page.ids.add(item_id)
        if tag == "a" and "name" in a and a["name"].strip():
            self.page.ids.add(a["name"])
        if tag == "img" and "alt" not in a:
            self._error("MISSING_IMAGE_ALT", lineno, "Images need an alt attribute; empty alt is valid for decoration")
        if tag in {"a", "area"} and "ping" in a:
            self._error("LINK_PING_NOT_ALLOWED", lineno, "Hyperlink ping sends tracking requests when activated")
        if tag == "a":
            self._anchor_stack.append({"line": lineno, "attrs": a, "text": []})
        if tag == "img" and self._anchor_stack:
            cast_text = self._anchor_stack[-1]["text"]
            assert isinstance(cast_text, list)
            cast_text.append(a.get("alt", ""))
        for key, value in a.items():
            if re.match(r"^on[a-z]", key):
                self._error("EVENT_HANDLER_NOT_ALLOWED", lineno, f"Inline event handler {key} is not allowed")
            if key == "style":
                refs, errors = _css_references(value, self.page.file, lineno)
                self.page.references.extend(refs)
                self.findings.extend(errors)
        if tag in RESOURCE_ATTRIBUTES:
            for key in RESOURCE_ATTRIBUTES[tag]:
                if key in a:
                    vals = _srcset_urls(a[key]) if key == "srcset" else [a[key]]
                    self.page.references.extend(Reference(self.page.file, lineno, tag, key, v, True, tag in {"image", "use", "feimage"}) for v in vals)
        if tag == "link" and "imagesrcset" in a:
            self.page.references.extend(Reference(self.page.file, lineno, tag, "imagesrcset", v, True) for v in _srcset_urls(a["imagesrcset"]))
        if tag == "link" and "href" in a:
            rels = set(a.get("rel", "").lower().split())
            if rels & RESOURCE_LINK_RELS:
                self.page.references.append(Reference(self.page.file, lineno, tag, "href", a["href"], True))
            # Canonical and alternate links are metadata, not network fetches.
            elif rels & {"canonical", "alternate"}:
                self.page.references.append(Reference(self.page.file, lineno, tag, "href", a["href"], False))
        if tag in {"a", "area"} and "href" in a:
            self.page.references.append(Reference(self.page.file, lineno, tag, "href", a["href"], False, True))
        if tag == "form":
            self.findings.append(Finding("WARNING", "FORM_REVIEW", self.page.file, lineno, "Form submissions can collect data; review the corresponding privacy statement"))

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        lineno = self.getpos()[0]
        if tag == "head" and self._head_depth:
            self._head_depth -= 1
        if tag == "title" and self._title_depth:
            self._title_depth -= 1
            self.page.titles.append(" ".join(self._title_buf).strip())
            self._title_buf.clear()
        if tag == "style" and self._style_depth:
            self._style_depth -= 1
        if tag == "script" and self._script_depth:
            self._script_depth -= 1
        if tag == "a" and self._anchor_stack:
            entry = self._anchor_stack.pop()
            attrs = entry["attrs"]
            values = entry["text"]
            assert isinstance(attrs, dict) and isinstance(values, list)
            if "href" in attrs and not (" ".join(values).strip() or attrs.get("aria-label", "").strip()):
                self._error("UNNAMED_LINK", int(entry["line"]), "Navigational link has no text or aria-label")
        if tag == "h1" and self._heading_stack:
            chunks = self._heading_stack.pop()
            if not " ".join(chunks).strip():
                self._error("EMPTY_H1", lineno, "The main heading must contain readable text")
        if tag in self.page.landmark_count:
            if not self._landmark_open:
                self._error("UNMATCHED_LANDMARK_CLOSE", lineno, f"Unexpected closing </{tag}>")
            elif self._landmark_open[-1][0] == tag:
                self._landmark_open.pop()
            else:
                self._error("LANDMARK_NESTING", lineno, f"Unexpected closing </{tag}>; verify landmark nesting")
                for i in range(len(self._landmark_open) - 1, -1, -1):
                    if self._landmark_open[i][0] == tag:
                        self._landmark_open.pop(i)
                        break

    def handle_data(self, data: str) -> None:
        if self._title_depth:
            self._title_buf.append(data)
        if self._style_depth:
            self._style_chunks.append((self.getpos()[0], data))
        if not (self._style_depth or self._script_depth or self._head_depth):
            self.page.readable_text.append(data)
            if self._anchor_stack:
                values = self._anchor_stack[-1]["text"]
                assert isinstance(values, list)
                values.append(data)
            if self._heading_stack:
                self._heading_stack[-1].append(data)

    def finish(self) -> tuple[Page, list[Finding]]:
        p = self.page
        if not p.lang:
            self._error("MISSING_LANG", 1, "The document needs <html lang=...>")
        if self._title_nodes != 1 or len(p.titles) != 1 or not p.titles[0]:
            self._error("PAGE_TITLE", 1, "Exactly one nonempty <title> is required")
        for tag in ("header", "nav", "main", "footer", "h1"):
            count = p.landmark_count[tag]
            if tag == "nav":
                if not count:
                    self._error("LANDMARK_MISSING", 1, "A <nav> landmark is required")
            elif count != 1:
                self._error("LANDMARK_COUNT", 1, f"Exactly one <{tag}> is required; found {count}")
        if p.landmark_count["nav"] > 1 and any(not name for name in self._nav_labels):
            self._error("NAV_LABEL_MISSING", 1, "Each of multiple navigation landmarks must have an aria-label")
        for tag, line in self._landmark_open:
            self._error("UNCLOSED_LANDMARK", line, f"Opening <{tag}> has no matching closing tag")
        for line, text in self._style_chunks:
            refs, errors = _css_references(text, p.file, line)
            p.references.extend(refs)
            self.findings.extend(errors)
        return p, self.findings


def _site_file_names(root: Path, result: Result) -> tuple[list[Path], list[Path]]:
    html: list[Path] = []
    css: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (Path(dirpath) / d).is_symlink())
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.suffix.lower() not in {".html", ".css"}:
                continue
            if not path.resolve().is_relative_to(root):
                rel = path.relative_to(root).as_posix()
                result.findings.append(Finding("ERROR", "FILE_OUTSIDE_SITE", rel, 1, "Linked source file resolves outside the site root"))
                continue
            (html if path.suffix.lower() == ".html" else css).append(path)
    return sorted(html), sorted(css)


def _evaluate_reference(ref: Reference, root: Path, pages: dict[str, Page], result: Result) -> None:
    raw = ref.url.strip()
    if not raw:
        if ref.resource:
            result.findings.append(Finding("ERROR", "EMPTY_RESOURCE", ref.file, ref.line, f"Empty {ref.tag}[{ref.attribute}] reference"))
        return
    if re.search(r"[\x00-\x1f\\]", raw):
        result.findings.append(Finding("ERROR", "INVALID_URL", ref.file, ref.line, "Reference contains control characters or backslashes"))
        return
    try:
        uri = urlsplit(raw)
    except ValueError:
        result.findings.append(Finding("ERROR", "INVALID_URL", ref.file, ref.line, "Cannot parse reference URL"))
        return
    query = parse_qsl(uri.query, keep_blank_values=True)
    for key, _ in query:
        name = key.casefold()
        if name.startswith("utm_") or name in TRACKING_PARAMETERS:
            result.findings.append(Finding("ERROR", "TRACKING_PARAMETER", ref.file, ref.line, f"Tracking query parameter '{key}' in reference"))
    remote = raw.startswith("//") or uri.scheme.lower() in {"https", "http"}
    if remote:
        if ref.resource:
            result.findings.append(Finding("ERROR", "REMOTE_RESOURCE", ref.file, ref.line, f"Remote resource is prohibited: {ref.tag}[{ref.attribute}]") )
        else:
            result.external_navigation += 1
        return
    if uri.scheme:
        if not ref.resource and uri.scheme.lower() in {"mailto", "tel"}:
            return
        result.findings.append(Finding("ERROR", "UNSAFE_SCHEME", ref.file, ref.line, f"Unsupported reference URL scheme: {uri.scheme.lower()}"))
        return
    if ref.resource and (raw.startswith("#") or raw.startswith("?")):
        # CSS fragment references such as SVG filters do not initiate a request.
        if ref.tag == "css" and raw.startswith("#"):
            return
        if ref.tag in {"image", "use", "feimage"} and raw.startswith("#"):
            pass
        else:
            result.findings.append(Finding("ERROR", "INVALID_RESOURCE", ref.file, ref.line, "Resource reference does not identify a local file"))
            return
    path_part = unquote(uri.path)
    if "\x00" in path_part or "\\" in path_part:
        result.findings.append(Finding("ERROR", "INVALID_LOCAL_PATH", ref.file, ref.line, "Decoded local path is unsafe"))
        return
    from_file = root / ref.file
    if path_part.startswith("/"):
        target = root / path_part.lstrip("/")
    elif path_part:
        target = from_file.parent / path_part
    else:
        target = from_file
    target = target.resolve(strict=False)
    if not target.is_relative_to(root):
        result.findings.append(Finding("ERROR", "PATH_ESCAPES_SITE", ref.file, ref.line, "Reference resolves outside the site root"))
        return
    # Treat trailing slash as directory index, with offline deterministic behavior.
    if path_part.endswith("/") or target.is_dir():
        target = target / "index.html"
    result.local_references += 1
    if not target.is_file():
        result.findings.append(Finding("ERROR", "BROKEN_LOCAL_LINK", ref.file, ref.line, f"Missing local target: {target.relative_to(root).as_posix()}"))
        return
    if ref.resource and ref.tag in {"img", "source", "input"} and TRACKING_PATH_RE.search(path_part):
        result.findings.append(Finding("ERROR", "TRACKING_ENDPOINT", ref.file, ref.line, "Tracking-like image resource path is not allowed"))
    if ref.fragment_check and uri.fragment and target.suffix.lower() == ".html":
        fragment = unquote(uri.fragment)
        key = target.relative_to(root).as_posix()
        page = pages.get(key)
        if page is not None and fragment not in page.ids:
            result.findings.append(Finding("ERROR", "BROKEN_FRAGMENT", ref.file, ref.line, f"Missing fragment '#{fragment}' in {key}"))


def _privacy_claims(page: Page | None, result: Result) -> None:
    if page is None:
        return
    text = re.sub(r"\s+", " ", " ".join(page.readable_text)).strip()
    for label, patterns in (("analytics", NEGATIVE_ANALYTICS), ("tracking", NEGATIVE_TRACKING)):
        if not any(pattern.search(text) for pattern in patterns):
            result.findings.append(Finding("ERROR", "PRIVACY_CLAIM_MISSING", page.file, 1, f"Privacy policy needs an explicit, unambiguous no-{label} statement"))
    for label, patterns in (("analytics", POSITIVE_ANALYTICS), ("tracking", POSITIVE_TRACKING)):
        if any(pattern.search(text) for pattern in patterns):
            result.findings.append(Finding("ERROR", "PRIVACY_CLAIM_CONTRADICTION", page.file, 1, f"Privacy text includes an affirmative {label} statement"))


def audit_site(site_root: str | Path, *, environ: dict[str, str] | None = None) -> Result:
    root = Path(site_root).expanduser().resolve()
    result = Result(root=str(root))
    if not flag_enabled(environ):
        result.disabled = True
        return result
    if not root.is_dir():
        result.findings.append(Finding("ERROR", "SITE_ROOT_MISSING", ".", 1, "Site root is not a directory"))
        return result
    pages: dict[str, Page] = {}
    html_files, css_files = _site_file_names(root, result)
    result.html_files = len(html_files)
    result.css_files = len(css_files)
    for required in REQUIRED_PAGES:
        path = root / required
        if not path.is_file():
            result.findings.append(Finding("ERROR", "REQUIRED_PAGE_MISSING", required, 1, "Required site page is missing"))
    if not html_files:
        result.findings.append(Finding("ERROR", "NO_HTML_FILES", ".", 1, "No HTML pages were found"))
    refs: list[Reference] = []
    for path in html_files:
        rel = path.relative_to(root).as_posix()
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            result.findings.append(Finding("ERROR", "FILE_READ_ERROR", rel, 1, f"Cannot read UTF-8 HTML: {type(exc).__name__}"))
            continue
        parser = _PageParser(rel)
        try:
            parser.feed(raw)
            parser.close()
        except Exception as exc:
            result.findings.append(Finding("ERROR", "HTML_PARSE_ERROR", rel, 1, f"Parser rejected HTML: {type(exc).__name__}"))
            continue
        page, findings = parser.finish()
        pages[rel] = page
        refs.extend(page.references)
        result.findings.extend(findings)
    for path in css_files:
        rel = path.relative_to(root).as_posix()
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            result.findings.append(Finding("ERROR", "FILE_READ_ERROR", rel, 1, f"Cannot read UTF-8 CSS: {type(exc).__name__}"))
            continue
        css_refs, css_findings = _css_references(raw, rel)
        refs.extend(css_refs)
        result.findings.extend(css_findings)
    for ref in refs:
        _evaluate_reference(ref, root, pages, result)
    _privacy_claims(pages.get("privacy-policy.html"), result)
    result.findings.sort(key=lambda f: (f.file, f.line, f.rule, f.detail))
    return result


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-root", default=".", help="Path to the unmodified static site root")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    options = parser.parse_args(argv)
    result = audit_site(options.site_root)
    if options.format == "json":
        print(json.dumps(result.as_json(), sort_keys=True, indent=2))
    elif result.disabled:
        print(f"DISABLED|{FLAG}=OFF|site files untouched")
        print("ALL=true")
    else:
        for f in result.findings:
            print(f"{f.severity}|{f.rule}|{f.file}:{f.line}|{f.detail}")
        print(f"CHECKED|html={result.html_files}|css={result.css_files}|local_references={result.local_references}|external_navigation_unverified={result.external_navigation}")
        print(f"ALL={'true' if result.ok else 'false'}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(cli())
