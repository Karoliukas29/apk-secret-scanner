#!/usr/bin/env python3
"""
apk-scanner.py — Scan APKs for hardcoded secrets, API keys, and sensitive strings.

Handles: .apk  .xapk (APKPure bundle)  .aab (Android App Bundle)

Usage:
  apk-scanner.py /path/to/apks/         # scan all APKs in a directory
  apk-scanner.py single.apk             # scan one file
  apk-scanner.py target/ --json         # output full JSON
  apk-scanner.py target/ --min-severity HIGH
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

@dataclass
class SecretPattern:
    name: str
    regex: str
    severity: str           # CRITICAL | HIGH | MEDIUM
    description: str
    case_sensitive: bool = False  # True = compile without IGNORECASE

# Patterns whose prefixes are fixed-case identifiers (e.g. AKIA, AIzaSy) must be
# case_sensitive=True so we don't match random lowercase substrings.
PATTERNS = [
    SecretPattern("aws_access_key",      r"AKIA[0-9A-Z]{16}",                                          "CRITICAL", "AWS IAM Access Key",           case_sensitive=True),
    SecretPattern("aws_sts_token",       r"ASIA[0-9A-Z]{16}",                                          "CRITICAL", "AWS STS Session Token",         case_sensitive=True),
    SecretPattern("google_api_key",      r"AIzaSy[0-9A-Za-z_\-]{33}",                                  "HIGH",     "Google / Firebase API Key",     case_sensitive=True),
    SecretPattern("firebase_db_url",     r"https://[a-z0-9\-]+\.firebaseio\.com",                       "MEDIUM",   "Firebase Realtime DB URL"),
    SecretPattern("gcp_service_account", r'"type"\s*:\s*"service_account"',                             "HIGH",     "GCP Service Account JSON"),
    SecretPattern("stripe_live_pub",     r"pk_live_[0-9a-zA-Z]{20,}",                                  "CRITICAL", "Stripe Live Publishable Key",   case_sensitive=True),
    SecretPattern("stripe_live_secret",  r"sk_live_[0-9a-zA-Z]{20,}",                                  "CRITICAL", "Stripe Live Secret Key",        case_sensitive=True),
    SecretPattern("stripe_live_rest",    r"rk_live_[0-9a-zA-Z]{20,}",                                  "CRITICAL", "Stripe Live Restricted Key",    case_sensitive=True),
    SecretPattern("stripe_test_secret",  r"sk_test_[0-9a-zA-Z]{20,}",                                  "HIGH",     "Stripe Test Secret Key",        case_sensitive=True),
    SecretPattern("stripe_test_pub",     r"pk_test_[0-9a-zA-Z]{20,}",                                  "MEDIUM",   "Stripe Test Publishable Key",   case_sensitive=True),
    SecretPattern("sendgrid_key",        r"SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}",              "CRITICAL", "SendGrid API Key",               case_sensitive=True),
    SecretPattern("mailgun_key",         r"key-[0-9a-zA-Z]{32}",                                        "HIGH",     "Mailgun API Key"),
    SecretPattern("mailchimp_key",       r"[0-9a-f]{32}-us[0-9]{1,2}",                                 "HIGH",     "Mailchimp API Key"),
    # negative lookbehind prevents matching inside Ethereum tx hashes (also 32 hex chars)
    SecretPattern("twilio_sid",          r"(?<![0-9a-fA-F])AC[0-9a-f]{32}(?![0-9a-fA-F])",            "HIGH",     "Twilio Account SID",            case_sensitive=True),
    SecretPattern("github_pat",          r"(ghp_|ghs_|gho_|ghu_)[a-zA-Z0-9]{36,}",                    "CRITICAL", "GitHub Personal Access Token",  case_sensitive=True),
    SecretPattern("slack_token",         r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24,}",   "CRITICAL", "Slack Token",                   case_sensitive=True),
    # bare EAA matches PNG base64 data, so require a key name before it
    SecretPattern("facebook_token",      r'(?:access_token|app_token|facebook_token|fb_token|PAGE_ACCESS_TOKEN)["\s=:]+EAA[0-9A-Za-z]{20,}', "HIGH", "Facebook Access Token"),
    SecretPattern("twitter_key",         r"twitter.{0,20}['\"][0-9a-zA-Z]{35,44}['\"]",               "HIGH",     "Twitter API Key"),
    SecretPattern("openai_key_old",      r"sk-[a-zA-Z0-9]{48}(?![a-zA-Z0-9_\-])",                     "CRITICAL", "OpenAI Secret Key",             case_sensitive=True),
    SecretPattern("openai_key_new",      r"sk-proj-[a-zA-Z0-9_\-]{80,}",                               "CRITICAL", "OpenAI Project Key",            case_sensitive=True),
    SecretPattern("mapbox_token",        r"pk\.[a-zA-Z0-9]{60,}\.[a-zA-Z0-9]{20,}",                   "HIGH",     "Mapbox Access Token",           case_sensitive=True),
    SecretPattern("google_maps_key",     r"maps.{0,10}key.{0,10}AIzaSy[0-9A-Za-z_\-]{33}",           "HIGH",     "Google Maps API Key"),
    SecretPattern("private_key",         r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",    "CRITICAL", "Private Key Material"),
    SecretPattern("pgp_private",         r"-----BEGIN PGP PRIVATE KEY BLOCK-----",                     "CRITICAL", "PGP Private Key"),
    SecretPattern("jwt_token",           r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "MEDIUM", "JWT Token",               case_sensitive=True),
    SecretPattern("bearer_token",        r'[Aa]uthorization["\s:]+Bearer\s+[A-Za-z0-9_\-\.]{20,}',   "MEDIUM",   "Hardcoded Bearer Token"),
    # exclude \n\r to prevent matching across DEX string boundaries (extractor joins runs with \n)
    SecretPattern("hardcoded_password",  r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\'\n\r]{6,})["\']',  "MEDIUM",   "Hardcoded Password"),
    SecretPattern("hardcoded_secret",    r'(?:secret|api_key|apikey|api-key|token)\s*[=:]\s*["\']([^"\'\n\r]{8,})["\']', "MEDIUM", "Hardcoded Secret / Token"),
    SecretPattern("hardcoded_auth",      r'(?:auth_token|access_token|client_secret)\s*[=:]\s*["\']([^"\'\n\r]{8,})["\']', "HIGH", "Hardcoded Auth Token"),
]

def _compile(p):
    flags = re.DOTALL if p.case_sensitive else re.DOTALL | re.IGNORECASE
    return (p, re.compile(p.regex, flags))

COMPILED = [_compile(p) for p in PATTERNS]

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "CLEAN": 1}

TEXT_EXTENSIONS = {
    ".xml", ".json", ".txt", ".properties", ".html", ".js",
    ".yaml", ".yml", ".cfg", ".conf", ".gradle", ".plist",
    ".kt", ".java", ".proto", ".env",
}

# Skip entries larger than this as text (avoids resources.arsc, large compiled tables)
MAX_TEXT_BYTES = 4 * 1024 * 1024

SUPPORTED_EXTENSIONS = {".apk", ".xapk", ".aab"}


@dataclass
class Finding:
    pattern_name: str
    severity: str
    description: str
    value: str
    file: str
    context: str = ""
    source: str = "regex"

@dataclass
class ApkResult:
    apk_name: str
    apk_path: str
    file_type: str = "apk"          # apk | xapk | aab
    verdict: str = "CLEAN"
    findings: list = field(default_factory=list)
    apkleaks_summary: str = ""
    scan_stats: dict = field(default_factory=dict)  # text_files, dex_files, inner_apks
    error: str = ""


_PLACEHOLDER_RE = re.compile(
    r'^(?:[x\-]{6,}|[0\-]{6,}|your[_\- ]|example[_\- ]|sample[_\- ]|dummy|placeholder|insert[_\- ]|<[^>]+>|\$\{[^}]+\}|test[_\- ]key|demo)',
    re.IGNORECASE
)

def _is_likely_placeholder(value):
    quoted = re.search(r'["\']([^"\']{4,})["\']', value)
    secret = quoted.group(1) if quoted else value
    return bool(_PLACEHOLDER_RE.match(secret))


def scan_text(content, source_file):
    findings = []
    seen = set()
    for pattern, regex in COMPILED:
        for match in regex.finditer(content):
            value = match.group(0)

            # Private key / PGP: skip if the closing footer appears within 200 chars of the
            # opening header — that means it's a PEM parser constant, not real key material.
            if pattern.name in ("private_key", "pgp_private"):
                after = content[match.end():match.end() + 200]
                if "-----END" in after:
                    continue

            if pattern.name in ("hardcoded_secret", "hardcoded_password", "hardcoded_auth"):
                if _is_likely_placeholder(value):
                    continue

            key = (pattern.name, value[:80])
            if key in seen:
                continue
            seen.add(key)
            start = max(0, match.start() - 80)
            end = min(len(content), match.end() + 80)
            context = content[start:end].replace("\n", " ").strip()
            findings.append(Finding(
                pattern_name=pattern.name,
                severity=pattern.severity,
                description=pattern.description,
                value=value[:150],
                file=source_file,
                context=context[:220],
                source="regex",
            ))
    return findings


def extract_dex_strings(dex_bytes):
    """Extract printable ASCII runs >= 8 chars from DEX bytecode without external tools."""
    content = dex_bytes.decode("latin-1", errors="replace")
    return "\n".join(re.findall(r'[ -~]{8,}', content))


def run_apkleaks(apk_path, tmp_dir):
    """Run apkleaks if installed; return a short summary string."""
    out_file = os.path.join(tmp_dir, "apkleaks_out.json")
    try:
        result = subprocess.run(
            ["apkleaks", "-f", str(apk_path), "-o", out_file],
            capture_output=True, text=True, timeout=90,
        )
        if os.path.exists(out_file):
            try:
                data = json.loads(Path(out_file).read_text())
                hits = {k: v for k, v in data.items() if v}
                if hits:
                    parts = [f"{k}: {', '.join(str(x) for x in v[:3])}"
                             for k, v in list(hits.items())[:10]]
                    return "; ".join(parts)
            except Exception:
                return result.stdout[:500].strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return ""


def compute_verdict(findings):
    if not findings:
        return "CLEAN"
    best = max(SEVERITY_RANK.get(f.severity, 0) for f in findings)
    return {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "CLEAN"}.get(best, "CLEAN")


def _scan_zip_contents(zip_path, path_prefix, seen_global, dex_prefix=None):
    """
    Scan a single ZIP file (APK or inner APK) for secrets.
    path_prefix: label to prepend to file paths in findings (e.g. "base/")
    dex_prefix:  where to look for DEX files (None = root, "base/dex/" for AAB)
    Returns (findings, stats_dict)
    """
    all_findings = []
    stats = {"text_files": 0, "dex_files": 0}

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            members = zf.infolist()

            # 1. Text resource files
            for member in members:
                name = member.filename
                ext = Path(name).suffix.lower()
                if ext not in TEXT_EXTENSIONS:
                    continue
                if member.file_size > MAX_TEXT_BYTES:
                    continue
                try:
                    content = zf.read(name).decode("utf-8", errors="ignore")
                    label = f"{path_prefix}{name}"
                    for f in scan_text(content, label):
                        k = (f.pattern_name, f.value[:80])
                        if k not in seen_global:
                            seen_global.add(k)
                            all_findings.append(f)
                    stats["text_files"] += 1
                except Exception:
                    continue

            # 2. DEX string literals
            if dex_prefix is None:
                # Standard APK: classes.dex, classes2.dex, ... at root
                dex_names = [m.filename for m in members
                             if re.match(r"classes\d*\.dex$", m.filename)]
            else:
                # AAB: base/dex/classes.dex etc.
                dex_names = [m.filename for m in members
                             if m.filename.startswith(dex_prefix) and m.filename.endswith(".dex")]

            for dex_name in dex_names[:6]:
                try:
                    dex_bytes = zf.read(dex_name)
                    dex_strings = extract_dex_strings(dex_bytes)
                    label = f"{path_prefix}{dex_name} [strings]"
                    for f in scan_text(dex_strings, label):
                        k = (f.pattern_name, f.value[:80])
                        if k not in seen_global:
                            seen_global.add(k)
                            all_findings.append(f)
                    stats["dex_files"] += 1
                except Exception:
                    continue

    except zipfile.BadZipFile:
        return None, stats  # signal bad zip to caller

    return all_findings, stats


def scan_apk_file(apk_path, use_apkleaks, min_rank, seen_global, tmp):
    """Scan a plain .apk file. Returns (findings, stats, apkleaks_summary, error)."""
    findings, stats = _scan_zip_contents(apk_path, "", seen_global)
    if findings is None:
        return [], stats, "", "Not a valid APK (bad ZIP)"
    apkleaks_summary = run_apkleaks(apk_path, tmp) if use_apkleaks else ""
    return findings, stats, apkleaks_summary, ""


def scan_xapk_file(xapk_path, use_apkleaks, min_rank, seen_global, tmp):
    """
    Unpack an XAPK (APKPure bundle) and scan each inner APK.
    XAPK structure: <package>.apk + config.*.apk + manifest.json + icon.png
    """
    findings = []
    stats = {"text_files": 0, "dex_files": 0, "inner_apks": 0}
    apkleaks_summary = ""
    error = ""

    try:
        with zipfile.ZipFile(xapk_path, "r") as outer:
            # Resolve package name from manifest.json for ordering
            pkg_name = None
            if "manifest.json" in outer.namelist():
                try:
                    manifest = json.loads(outer.read("manifest.json").decode("utf-8"))
                    pkg_name = manifest.get("package_name", "")
                except Exception:
                    pass

            inner_apk_names = [n for n in outer.namelist() if n.endswith(".apk")]
            if not inner_apk_names:
                error = "No inner APK found inside XAPK"
                return findings, stats, apkleaks_summary, error

            # Sort: base APK first (named after package_name), then configs
            def apk_sort_key(name):
                base = Path(name).name
                if pkg_name and base == f"{pkg_name}.apk":
                    return (0, name)
                if base.startswith("config."):
                    return (2, name)
                return (1, name)

            inner_apk_names.sort(key=apk_sort_key)

            apkleaks_done = False
            for inner_name in inner_apk_names:
                inner_tmp = Path(tmp) / inner_name
                inner_tmp.parent.mkdir(parents=True, exist_ok=True)
                with open(inner_tmp, "wb") as f_out:
                    f_out.write(outer.read(inner_name))

                prefix = f"{inner_name}/"
                inner_findings, inner_stats = _scan_zip_contents(inner_tmp, prefix, seen_global)
                if inner_findings is None:
                    continue  # skip corrupt inner APK

                findings.extend(inner_findings)
                stats["text_files"] += inner_stats["text_files"]
                stats["dex_files"] += inner_stats["dex_files"]
                stats["inner_apks"] += 1

                # Run apkleaks on the base APK (first in sorted order = main/base APK)
                if use_apkleaks and not apkleaks_done:
                    apkleaks_summary = run_apkleaks(inner_tmp, tmp)
                    apkleaks_done = True

    except zipfile.BadZipFile:
        error = "Not a valid XAPK (bad ZIP)"

    return findings, stats, apkleaks_summary, error


def scan_aab_file(aab_path, use_apkleaks, min_rank, seen_global, tmp):
    """
    Scan an Android App Bundle (.aab).
    AAB layout: base/manifest/ base/dex/ base/assets/ base/root/ feature1/dex/ ...
    """
    findings, stats = _scan_zip_contents(
        aab_path,
        path_prefix="",
        seen_global=seen_global,
        dex_prefix="base/dex/",
    )

    # Also pick up dex from dynamic feature modules
    try:
        with zipfile.ZipFile(aab_path, "r") as zf:
            feature_dex = [m.filename for m in zf.infolist()
                           if re.match(r"[^/]+/dex/classes.*\.dex$", m.filename)
                           and not m.filename.startswith("base/")]
            for dex_name in feature_dex[:4]:
                try:
                    dex_bytes = zf.read(dex_name)
                    dex_strings = extract_dex_strings(dex_bytes)
                    label = f"{dex_name} [strings]"
                    for f in scan_text(dex_strings, label):
                        k = (f.pattern_name, f.value[:80])
                        if k not in seen_global:
                            seen_global.add(k)
                            findings.append(f)
                    stats["dex_files"] += 1
                except Exception:
                    continue
    except Exception:
        pass

    if findings is None:
        return [], stats, "", "Not a valid AAB (bad ZIP)"

    return findings, stats, "", ""  # apkleaks doesn't support AAB


def scan_file(file_path, use_apkleaks=True, min_severity="MEDIUM"):
    """Scan any supported file type. Returns ApkResult."""
    ext = file_path.suffix.lower()
    result = ApkResult(
        apk_name=file_path.name,
        apk_path=str(file_path),
        file_type=ext.lstrip("."),
    )
    min_rank = SEVERITY_RANK.get(min_severity, 2)
    seen_global = set()

    if not file_path.exists():
        result.error = "File not found"
        return result

    with tempfile.TemporaryDirectory(prefix="apk_scan_") as tmp:
        if ext == ".xapk":
            findings, stats, apkleaks_summary, error = scan_xapk_file(
                file_path, use_apkleaks, min_rank, seen_global, tmp)
        elif ext == ".aab":
            findings, stats, apkleaks_summary, error = scan_aab_file(
                file_path, use_apkleaks, min_rank, seen_global, tmp)
        else:  # .apk (default)
            findings, stats, apkleaks_summary, error = scan_apk_file(
                file_path, use_apkleaks, min_rank, seen_global, tmp)

    result.error = error
    result.apkleaks_summary = apkleaks_summary
    result.scan_stats = stats

    # Apply severity filter
    findings = [f for f in findings if SEVERITY_RANK.get(f.severity, 0) >= min_rank]
    result.findings = findings
    result.verdict = compute_verdict(findings)
    return result


def redact(value):
    if len(value) <= 10:
        return value
    return value[:6] + "..." + value[-4:]


def _stats_label(result):
    s = result.scan_stats
    parts = []
    if s.get("inner_apks"):
        parts.append(f"{s['inner_apks']} inner APK{'s' if s['inner_apks'] != 1 else ''}")
    if s.get("text_files"):
        parts.append(f"{s['text_files']} text files")
    if s.get("dex_files"):
        parts.append(f"{s['dex_files']} DEX")
    return ", ".join(parts) if parts else "—"


def generate_markdown_report(results, session_name, output_path):
    total = len(results)
    by_verdict = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "CLEAN": [], "ERROR": []}
    for r in results:
        bucket = "ERROR" if r.error else r.verdict
        by_verdict.setdefault(bucket, []).append(r)

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    critical_n = len(by_verdict["CRITICAL"])
    high_n     = len(by_verdict["HIGH"])
    medium_n   = len(by_verdict["MEDIUM"])
    clean_n    = len(by_verdict["CLEAN"])
    error_n    = len(by_verdict.get("ERROR", []))
    vuln_n     = critical_n + high_n

    lines = [
        f"# APK Secret Scan — {session_name}",
        f"**Scanned:** {now}  |  **Files:** {total}  |  **Patterns:** {len(PATTERNS)}",
        "",
        "## Summary",
        "",
        "| Verdict | Count | Share |",
        "|---------|------:|------:|",
        f"| 🔴 CRITICAL | {critical_n} | {critical_n/total*100:.0f}% |",
        f"| 🟠 HIGH | {high_n} | {high_n/total*100:.0f}% |",
        f"| 🟡 MEDIUM | {medium_n} | {medium_n/total*100:.0f}% |",
        f"| 🟢 CLEAN | {clean_n} | {clean_n/total*100:.0f}% |",
    ]
    if error_n:
        lines.append(f"| ⚠ ERRORS | {error_n} | {error_n/total*100:.0f}% |")

    lines += ["", "---", "", "## LinkedIn Article Hook", ""]

    if vuln_n:
        lines.append(
            f"> I scanned **{total} Android apps** for exposed secrets. "
            f"**{vuln_n} of them** had hardcoded API keys or credentials — "
            f"some from live production systems. Here's what I found. 🧵"
        )
    else:
        lines.append(
            f"> I ran automated secret scanning across **{total} Android apps**. "
            f"Here are the findings — some surprising, some reassuring. 🧵"
        )

    type_counts = {}
    for r in results:
        for f in r.findings:
            type_counts[f.description] = type_counts.get(f.description, 0) + 1
    if type_counts:
        lines += ["", "**Top finding types:**"]
        for desc, count in sorted(type_counts.items(), key=lambda x: -x[1])[:6]:
            lines.append(f"- {desc}: {count} app(s)")

    lines += ["", "---", ""]

    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}
    for verdict in ["CRITICAL", "HIGH", "MEDIUM"]:
        apps = by_verdict.get(verdict, [])
        if not apps:
            continue
        lines += [f"## {icons[verdict]} {verdict} ({len(apps)} apps)", ""]
        for r in apps:
            type_badge = f" `[{r.file_type.upper()}]`" if r.file_type != "apk" else ""
            lines.append(f"### `{r.apk_name}`{type_badge}")
            lines.append(f"_Scanned: {_stats_label(r)}_")
            lines.append("")
            for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
                for f in [x for x in r.findings if x.severity == sev]:
                    lines.append(f"- **[{f.severity}]** {f.description}")
                    lines.append(f"  - Value:   `{redact(f.value)}`")
                    lines.append(f"  - File:    `{f.file}`")
                    if f.context and len(f.context) > len(f.value) + 10:
                        ctx = f.context[:150].replace("`", "'")
                        lines.append(f"  - Context: `{ctx}`")
            if r.apkleaks_summary:
                lines += [
                    "",
                    "<details><summary>apkleaks hits</summary>",
                    "",
                    f"```\n{r.apkleaks_summary[:1500]}\n```",
                    "</details>",
                ]
            lines.append("")

    clean_apps = by_verdict.get("CLEAN", [])
    if clean_apps:
        lines += [f"## 🟢 CLEAN ({len(clean_apps)} apps)", ""]
        names = ", ".join(f"`{r.apk_name}`" for r in clean_apps)
        lines.append(f"No secrets detected: {names}")
        lines.append("")

    error_apps = by_verdict.get("ERROR", [])
    if error_apps:
        lines += [f"## ⚠ ERRORS ({len(error_apps)} files)", ""]
        for r in error_apps:
            lines.append(f"- `{r.apk_name}`: {r.error}")
        lines.append("")

    lines += [
        "---", "",
        "## Methodology", "",
        "Each file was scanned with three techniques:",
        "1. **Resource text scan** — XML, JSON, properties, assets unpacked from the archive",
        "2. **DEX string extraction** — printable string literals from compiled bytecode",
        "3. **apkleaks** — supplementary scan using a curated regex ruleset (APK + XAPK; skipped for AAB)",
        "",
        f"Supported formats: APK · XAPK (APKPure bundles, inner APKs extracted) · AAB (Android App Bundle)",
        f"Pattern library: {len(PATTERNS)} secret types — AWS, Stripe, Firebase, GitHub, OpenAI,",
        "SendGrid, Twilio, Slack, Mapbox, Mailchimp, JWT, private keys, and generic credentials.",
        "",
        "_Values are partially redacted in this report. Full values in `scan-results.json`._",
    ]

    output_path.write_text("\n".join(lines))
    return output_path


def generate_json_report(results, session_name, output_path):
    by_verdict = {}
    for r in results:
        by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1

    data = {
        "session": session_name,
        "scan_date": datetime.now().isoformat(),
        "total_files": len(results),
        "verdicts": by_verdict,
        "pattern_count": len(PATTERNS),
        "results": [
            {
                "file": r.apk_name,
                "file_type": r.file_type,
                "verdict": r.verdict,
                "finding_count": len(r.findings),
                "scan_stats": r.scan_stats,
                "apkleaks_summary": r.apkleaks_summary,
                "error": r.error,
                "findings": [
                    {
                        "type": f.pattern_name,
                        "severity": f.severity,
                        "description": f.description,
                        "value": f.value,
                        "file": f.file,
                        "context": f.context,
                        "source": f.source,
                    }
                    for f in r.findings
                ],
            }
            for r in results
        ],
    }
    output_path.write_text(json.dumps(data, indent=2))
    return output_path


_VERDICT_FOLDER = {
    "CRITICAL": "vulnerable",
    "HIGH":     "vulnerable",
    "MEDIUM":   "worth-checking",
    "CLEAN":    "not-vulnerable",
}
_VERDICT_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "CLEAN": "🟢"}


def _load_session_meta(output_dir):
    """Return dict of {appId: app_dict} from session.json, or {}."""
    session_json = output_dir / "session.json"
    if not session_json.exists():
        return {}
    try:
        sess = json.loads(session_json.read_text())
        return {a["appId"]: a for a in sess.get("apps", []) if "appId" in a}
    except Exception:
        return {}


def _pkg_from_filename(filename):
    """com.example.app.xapk → com.example.app"""
    p = Path(filename)
    # strip .xapk / .apk / .aab
    stem = p.stem
    # if the stem still has a known extension (e.g. .apk inside .xapk), strip again
    if Path(stem).suffix.lower() in SUPPORTED_EXTENSIONS:
        stem = Path(stem).stem
    return stem


_TRIAGE_HINTS = {
    "private_key":       ("Verify the full PEM block", "Check that base64 key bytes exist between header and footer — bare headers in DEX are often PEM parser constants, not real keys."),
    "pgp_private":       ("Verify the full PGP block", "Check that the block contains key material, not just a parser constant."),
    "aws_access_key":    ("Test if active", "Run: `AWS_ACCESS_KEY_ID=KEY AWS_SECRET_ACCESS_KEY=SECRET aws sts get-caller-identity --no-cli-pager`"),
    "aws_sts_token":     ("STS tokens are short-lived", "Verify it's still valid: set AWS_SESSION_TOKEN alongside the access key and call `aws sts get-caller-identity`."),
    "google_api_key":    ("Test and check restrictions", "Run: `curl 'https://maps.googleapis.com/maps/api/geocode/json?address=test&key=KEY'`. Also check API restrictions in Google Cloud Console."),
    "firebase_db_url":   ("Check public read access", "Open `DATABASE_URL/.json` in a browser — if it returns data without auth, rules are open."),
    "stripe_live_pub":   ("Publishable key — confirm live mode", "Publishable keys can't charge, but confirm it's live (not test) and report to the developer."),
    "stripe_live_secret":("CRITICAL — live secret key", "Run: `curl https://api.stripe.com/v1/charges -u KEY:` to confirm validity. Disclose responsibly before publishing."),
    "stripe_test_secret":("Test key — limited impact", "Confirms secrets in code but no production exposure. Still worth noting in the article."),
    "github_pat":        ("Test scope and access", "Run: `curl -H 'Authorization: token TOKEN' https://api.github.com/user` — check repos, org membership."),
    "slack_token":       ("Test if active", "Run: `curl 'https://slack.com/api/auth.test?token=TOKEN'`"),
    "sendgrid_key":      ("Test if active", "Run: `curl 'https://api.sendgrid.com/v3/scopes' -H 'Authorization: Bearer KEY'`"),
    "openai_key_old":    ("Test if active", "Run: `curl https://api.openai.com/v1/models -H 'Authorization: Bearer KEY'`"),
    "openai_key_new":    ("Test if active", "Run: `curl https://api.openai.com/v1/models -H 'Authorization: Bearer KEY'`"),
    "jwt_token":         ("Decode and check expiry", "Paste at jwt.io — look at `exp` (expiry) and `aud`/`scope` claims. If no `exp`, it may be permanent."),
    "bearer_token":      ("Replay the token", "Use Burp or curl to replay the `Authorization: Bearer TOKEN` header against the app's API endpoints."),
    "hardcoded_secret":  ("Verify it's a real value", "Check the context — is this a config constant or code template? Grep the decompiled source to see where it's used."),
    "hardcoded_password":("Find where it's used", "Decompile and grep for the literal value to find the login function. Confirm it's not a hardcoded default or test credential."),
    "hardcoded_auth":    ("Replay the token", "Use Burp to intercept traffic, or replay the token directly against the API to check if it's still valid."),
    "twilio_sid":        ("Confirm it's a Twilio SID", "Twilio Account SIDs start with `AC`. Verify with the Twilio console if you have the auth token too."),
    "mapbox_token":      ("Test permissions", "Run: `curl 'https://api.mapbox.com/tokens/v2?access_token=TOKEN'` to list scopes."),
}

def _triage_hint(finding):
    return _TRIAGE_HINTS.get(finding.pattern_name)


def _dynamic_checklist(findings):
    items = []
    names = {f.pattern_name for f in findings}

    if "private_key" in names or "pgp_private" in names:
        items.append("Extract the full PEM block from the decompiled source and verify it contains real key bytes")
    if names & {"aws_access_key", "aws_sts_token"}:
        items.append("Test the AWS key: `aws sts get-caller-identity` — check attached IAM policies")
    if names & {"stripe_live_secret", "stripe_live_pub", "stripe_live_rest"}:
        items.append("Test the Stripe key against the API — if live, disclose to developer before publishing")
    if names & {"stripe_test_secret", "stripe_test_pub"}:
        items.append("Confirm the Stripe key is test mode (sk_test_ / pk_test_) — note in article as misconfiguration")
    if names & {"google_api_key", "firebase_db_url"}:
        items.append("Check Firebase/GCP Console for API key restrictions and open database rules")
    if names & {"github_pat"}:
        items.append("Test GitHub PAT: `curl -H 'Authorization: token TOKEN' https://api.github.com/user`")
    if names & {"openai_key_old", "openai_key_new"}:
        items.append("Test OpenAI key: `curl https://api.openai.com/v1/models -H 'Authorization: Bearer KEY'`")
    if names & {"jwt_token", "bearer_token", "hardcoded_auth"}:
        items.append("Decode JWTs at jwt.io — replay bearer tokens in Burp against the app's API")
    if names & {"hardcoded_secret", "hardcoded_password"}:
        items.append("Grep the decompiled source for the literal value to find where it's used")
    if names & {"hardcoded_secret", "hardcoded_password", "hardcoded_auth"}:
        items.append("Confirm the value is not a test credential, default password, or code comment")

    # Always present
    items.append("Review AndroidManifest for exported components and deep links")
    items.append("Consider responsible disclosure to the developer before publishing")
    return items


def _write_app_note(path, result, meta):
    pkg = _pkg_from_filename(result.apk_name)
    icon = _VERDICT_ICON.get(result.verdict, "⚠")

    lines = [
        f"# {pkg}",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Verdict** | {icon} {result.verdict} |",
        f"| **File** | `{result.apk_name}` |",
        f"| **Type** | {result.file_type.upper()} |",
        f"| **Scanned** | {_stats_label(result)} |",
    ]

    if meta:
        title = meta.get("title") or pkg
        dev   = meta.get("developer") or "?"
        inst  = meta.get("installs") or "?"
        score = meta.get("score")
        rating_str = f"{score:.1f} / 5" if score else "—"
        lines += [
            f"| **App name** | {title} |",
            f"| **Developer** | {dev} |",
            f"| **Installs** | {inst} |",
            f"| **Rating** | {rating_str} |",
        ]

    lines += [""]

    # full values here — this file stays local, scan-report.md is the redacted copy
    if result.error:
        lines += ["## ⚠ Scan Error", "", f"> {result.error}", ""]
    elif result.findings:
        lines += ["## Findings", ""]
        for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
            sev_findings = [f for f in result.findings if f.severity == sev]
            if not sev_findings:
                continue
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}[sev]
            lines.append(f"### {sev_icon} {sev}")
            lines.append("")
            for f in sev_findings:
                hint = _triage_hint(f)
                lines += [
                    f"**{f.description}**",
                    f"- File:    `{f.file}`",
                    f"- Value:   `{f.value}`",   # full value — not redacted
                ]
                if f.context and len(f.context) > len(f.value) + 10:
                    lines.append(f"- Context: `{f.context[:250]}`")
                if hint:
                    lines.append(f"- Triage:  **{hint[0]}** — {hint[1]}")
                lines.append("")
    else:
        lines += ["## Findings", "", "_No secrets detected._", ""]

    checklist = _dynamic_checklist(result.findings) if result.findings else [
        "No secrets detected — review AndroidManifest and exported components manually",
        "Consider dynamic analysis (Burp + SSL unpin) to catch runtime secrets",
    ]
    lines += ["## Analysis Checklist", ""]
    for item in checklist:
        lines.append(f"- [ ] {item}")
    lines.append("")

    lines += [
        "## Quick Commands",
        "",
        "```bash",
        f"# Decompile (run from session directory)",
        f"jadx-gui apks/{result.apk_name}",
        "",
        f"# Full static analysis",
        f"jadx -d /tmp/{pkg}_src apks/{result.apk_name}",
        f"grep -r 'password\\|secret\\|api_key\\|token' /tmp/{pkg}_src/",
        "",
        f"# apkleaks",
        f"apkleaks -f apks/{result.apk_name} -o /tmp/{pkg}_leaks.json",
        "",
        f"# Install on connected device/emulator",
        f"adb install apks/{result.apk_name}",
        "",
        f"# Frida — SSL unpin then attach",
        f"frida-ssl-unpin  # source lab.env alias",
        f"objection -g {pkg} explore",
        "```",
    ]

    path.write_text("\n".join(lines))


def _write_readme(path, results, session_name, output_dir):
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    verdicts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "CLEAN": 0}
    for r in results:
        verdicts[r.verdict] = verdicts.get(r.verdict, 0) + 1

    total   = len(results)
    vuln_n  = verdicts["CRITICAL"] + verdicts["HIGH"]
    medium_n = verdicts["MEDIUM"]
    clean_n  = verdicts["CLEAN"]

    lines = [
        f"# {session_name}",
        "",
        f"**Generated:** {now}  |  **Files scanned:** {total}",
        "",
        "## Results at a Glance",
        "",
        "| Verdict | Count | Folder |",
        "|---------|------:|--------|",
        f"| 🔴 CRITICAL | {verdicts['CRITICAL']} | `vulnerable/` |",
        f"| 🟠 HIGH     | {verdicts['HIGH']}     | `vulnerable/` |",
        f"| 🟡 MEDIUM   | {verdicts['MEDIUM']}   | `worth-checking/` |",
        f"| 🟢 CLEAN    | {verdicts['CLEAN']}    | `not-vulnerable/` |",
        "",
    ]

    # Full app table sorted by severity
    lines += [
        "## All Apps",
        "",
        "| App | Verdict | Findings | Type | Notes |",
        "|-----|---------|----------|------|-------|",
    ]
    for r in sorted(results, key=lambda x: -SEVERITY_RANK.get(x.verdict, 0)):
        icon    = _VERDICT_ICON.get(r.verdict, "⚠")
        n       = len(r.findings)
        folder  = _VERDICT_FOLDER.get(r.verdict, "not-vulnerable")
        pkg     = _pkg_from_filename(r.apk_name)
        note_link = f"[{r.apk_name}]({folder}/{pkg}.md)" if n > 0 or r.error else r.apk_name
        top_finding = r.findings[0].description if r.findings else ("⚠ " + r.error if r.error else "—")
        lines.append(f"| {note_link} | {icon} {r.verdict} | {n} | {r.file_type.upper()} | {top_finding} |")

    hook_text = ""
    scan_report = output_dir / "scan-report.md"
    if scan_report.exists():
        content = scan_report.read_text()
        m = re.search(r"## LinkedIn Article Hook\n\n(> .+?)(?=\n\n[^>])", content, re.DOTALL)
        if m:
            hook_text = m.group(1).strip()

    if hook_text:
        lines += ["", "---", "", "## LinkedIn Article Hook", "", hook_text, ""]

    lines += [
        "---",
        "",
        "## Folder Guide",
        "",
        "```",
        "out/",
        "├── README.md              ← you are here",
        "├── reports/",
        "│   ├── scan-report.md     ← full scan report (redacted values)",
        "│   ├── article-brief.md   ← per-app Play Store metadata + VT results",
        "│   └── scan-results.json  ← machine-readable full data",
        "├── vulnerable/            ← CRITICAL + HIGH — analyse these first",
        "│   ├── <package>.xapk     ← symlink to ../apks/",
        "│   └── <package>.md       ← findings note (full values, checklist, commands)",
        "├── worth-checking/        <- MEDIUM — verify manually, may be false positives",
        "└── not-vulnerable/        ← CLEAN — no secrets detected",
        "```",
        "",
        "## Next Steps",
        "",
        "1. Open `vulnerable/` — each `.md` note has the full secret value and analysis commands",
        "2. Verify any MEDIUM finding is real before including it in an article",
        "3. Run `jadx-gui` on interesting APKs for deeper static analysis",
        "4. Use `reports/article-brief.md` for Play Store context and `scan-report.md` for the hook",
    ]

    path.write_text("\n".join(lines))


def generate_output_dir(results, output_dir, session_name):
    """Build the out/ workspace directory from scan results."""
    out = output_dir / "out"

    # Fresh rebuild every run
    if out.exists():
        shutil.rmtree(out)

    folders = {
        "vulnerable":     out / "vulnerable",
        "worth-checking": out / "worth-checking",
        "not-vulnerable": out / "not-vulnerable",
        "reports":        out / "reports",
    }
    for d in folders.values():
        d.mkdir(parents=True, exist_ok=True)

    # Play Store metadata from session.json (if present)
    session_meta = _load_session_meta(output_dir)

    apks_dir = output_dir / "apks"

    for r in results:
        folder_name = _VERDICT_FOLDER.get(r.verdict, "not-vulnerable")
        if r.error:
            folder_name = "worth-checking"
        dest = folders[folder_name]

        # Symlink the APK/XAPK/AAB file (relative path for portability)
        apk_src = apks_dir / r.apk_name
        if apk_src.exists():
            link = dest / r.apk_name
            try:
                link.symlink_to(f"../../apks/{r.apk_name}")
            except Exception:
                pass  # symlinks not supported on this fs — skip silently

        if folder_name != "not-vulnerable" or r.error:
            pkg = _pkg_from_filename(r.apk_name)
            meta = session_meta.get(pkg, {})
            _write_app_note(dest / f"{pkg}.md", r, meta)

    for fname in ["scan-report.md", "article-brief.md", "scan-results.json"]:
        src = output_dir / fname
        if src.exists():
            shutil.copy2(src, folders["reports"] / fname)

    # README
    _write_readme(out / "README.md", results, session_name, output_dir)

    return out


def main():
    p = argparse.ArgumentParser(
        description="APK Scanner — detect hardcoded secrets in APK / XAPK / AAB files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("target", help="File, APK directory, or hunt session directory")
    p.add_argument("--no-apkleaks", action="store_true", help="Skip apkleaks (faster)")
    p.add_argument("--json", action="store_true", help="Write scan-results.json")
    p.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM"], default="MEDIUM",
                   help="Minimum severity to report (default: MEDIUM)")
    p.add_argument("--output", help="Output directory (default: target directory)")
    args = p.parse_args()

    target = Path(args.target)

    # Resolve file list and output dir
    files = []
    session_name = ""
    output_dir = None

    if target.is_file() and target.suffix.lower() in SUPPORTED_EXTENSIONS:
        files = [target]
        session_name = target.stem
        output_dir = target.parent
    elif target.is_dir():
        apks_sub = target / "apks"
        search_dir = apks_sub if apks_sub.is_dir() else target
        for ext in SUPPORTED_EXTENSIONS:
            files += sorted(search_dir.glob(f"*{ext}"))
        session_name = target.name
        output_dir = target
    else:
        print(f"[!] Not found or unsupported: {target}")
        sys.exit(1)

    if not files:
        print(f"[!] No APK / XAPK / AAB files found in: {target}")
        sys.exit(1)

    if args.output:
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*64}")
    print(f"  APK Scanner")
    print(f"  Session  : {session_name}")
    print(f"  Files    : {len(files)}")
    print(f"  Patterns : {len(PATTERNS)} secret types")
    print(f"  Severity : {args.min_severity}+")
    if not args.no_apkleaks:
        print(f"  apkleaks : enabled (APK + XAPK base APK; skipped for AAB)")
    print(f"{'='*64}\n")

    results = []
    for i, f in enumerate(files, 1):
        ext = f.suffix.upper().lstrip(".")
        type_label = {"XAPK": " [XAPK]", "AAB": " [AAB]"}.get(ext, "")
        sys.stdout.write(f"[{i}/{len(files)}] {f.name:<52}{type_label}\n")
        sys.stdout.flush()

        r = scan_file(f, use_apkleaks=not args.no_apkleaks, min_severity=args.min_severity)

        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "CLEAN": "🟢"}.get(r.verdict, "⚠")
        n = len(r.findings)
        stats_str = _stats_label(r)

        if r.error:
            print(f"         ⚠  ERROR: {r.error}")
        else:
            print(f"         {icon} {r.verdict} — {n} finding{'s' if n != 1 else ''}  ({stats_str})")
            for f2 in sorted(r.findings, key=lambda x: -SEVERITY_RANK.get(x.severity, 0))[:3]:
                print(f"            [{f2.severity}] {f2.description}: {redact(f2.value)}")
            if n > 3:
                print(f"            ... and {n - 3} more")

        results.append(r)

    report_path = output_dir / "scan-report.md"
    generate_markdown_report(results, session_name, report_path)
    print(f"\n[+] Report      → {report_path}")

    # always written — output dir generation reads it, and useful for jq filtering
    json_path = output_dir / "scan-results.json"
    generate_json_report(results, session_name, json_path)
    print(f"[+] JSON        → {json_path}")

    # Build organised output directory
    out_dir = generate_output_dir(results, output_dir, session_name)
    print(f"[+] Output dir  → {out_dir}")

    verdicts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "CLEAN": 0}
    for r in results:
        verdicts[r.verdict] = verdicts.get(r.verdict, 0) + 1

    print(f"\n{'='*64}")
    print(f"  🔴 CRITICAL : {verdicts['CRITICAL']}")
    print(f"  🟠 HIGH     : {verdicts['HIGH']}")
    print(f"  🟡 MEDIUM   : {verdicts['MEDIUM']}")
    print(f"  🟢 CLEAN    : {verdicts['CLEAN']}")
    print(f"{'='*64}\n")

    return 0 if (verdicts["CRITICAL"] + verdicts["HIGH"]) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
