"""
Discover attack-surface entrypoints from full rootfs or partial analysis layouts.

This script is intentionally heuristic-heavy: it works on segmented/probe
layouts where only representative blobs or carved payloads are available.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.analyzer.scoring import extract_endpoints
from src.core.analyzer.sink_detector import detect_sinks, is_valid_sink
from src.core.scanner.scan_web import scan_web_surface

TEXT_EXTS = {
    ".txt", ".json", ".xml", ".cfg", ".conf", ".ini", ".lua", ".sh", ".cgi",
    ".asp", ".htm", ".html", ".js", ".css", ".php", ".pl", ".py",
}
SCAN_EXTS = TEXT_EXTS | {
    ".bin", ".so", ".cgi", ".7z", ".trx", ".img", ".chk", ".dat", ".pack",
    ".pkgtb", ".tar", ".gz", ".xz", ".lzma", ".ubifs",
}

DAEMON_HINTS = {
    "miniupnpd", "upnpd", "httpd", "boa", "lighttpd", "uhttpd", "nginx",
    "cwmp", "tr069", "rpcd", "dnsmasq", "udhcpd", "hostapd", "wifidog",
    "tdpserver", "connmode",
}
WEB_HINTS = {
    "/config", "/upload", "/restore", "/backup", "/boafrm", "/cgi-bin",
    "/soap", "/upnp", "/wanipconnection", "/wanpppconnection", "soapaction",
    "formupload", "formuploadfile", "firmware", "restore-file", "multipart",
}
PARSER_HINTS = {
    "xml", "json", "parser", "parse", "decode", "deserializ", "unmarshal",
    "untar", "tar -", "gzip", "inflate", "protobuf", "tlv", "packet",
}
INPUT_HINT_PATTERNS = [
    r"\b(filename|filepath|path|cmd|host|ipaddr|upload|restore|config|sid|realm|username|password|token|file|soapaction)\b",
    r"/(?:config|upload|restore|backup|diag|cgi-bin|boafrm|soap|upnp)[A-Za-z0-9_./?-]*",
]
MEMORY_HINTS = {
    "memcpy(", "strcpy(", "strcat(", "sprintf(", "snprintf(", "sscanf(",
}
EXEC_HINTS = {
    "system(", "popen(", "execl(", "execv(", "execve(", "execvp(",
    "/bin/sh", "sh -c", "os.execute", "io.popen", "luci.sys.call",
}


def load_json(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except Exception:
        return str(path)


def display_component_name(rel: str) -> str:
    rel = rel.replace("\\", "/")
    if len(rel) <= 120:
        return rel
    parts = rel.split("/")
    if len(parts) >= 2:
        tail = "/".join(parts[-2:])
        if len(tail) <= 120:
            return f".../{tail}"
    return f".../{parts[-1]}"


def infer_evidence_source(system_path: str, result: dict) -> str:
    sp = (system_path or "").lower()
    if "_segmented_partial_layout" in sp:
        return "segmented"
    if "_probe_partial_layout" in sp or ".offset_probe" in sp:
        return "probe"
    targets = result.get("container_targets") or []
    for target in targets:
        source_kind = str(target.get("source_kind") or "").lower()
        if "encrypted" in source_kind:
            return "probe"
    return "rootfs"


def candidate_roots(result: dict) -> list[Path]:
    roots: list[Path] = []
    seen = set()

    def add_path(raw: str | None) -> None:
        if not raw:
            return
        p = Path(raw)
        if not p.is_absolute():
            p = PROJECT_ROOT / p
        try:
            p = p.resolve()
        except Exception:
            p = p
        text = str(p)
        if text in seen:
            return
        if p.exists():
            roots.append(p)
            seen.add(text)

    analysis = result.get("analysis") or {}
    add_path(analysis.get("system_path"))
    add_path(analysis.get("vendor_path"))

    run_dir = result.get("run_dir")
    if run_dir:
        run_root = Path(run_dir)
        if not run_root.is_absolute():
            run_root = PROJECT_ROOT / run_root
        add_path(str(run_root / "container_targets"))

    for target in result.get("container_targets") or []:
        for key in ("dest", "src", "ciphertext_dest"):
            add_path(target.get(key))
        probe_bundle = target.get("probe_bundle") or {}
        add_path(probe_bundle.get("probe_dir"))

    return roots


def relevant_file(path: Path) -> bool:
    if not path.is_file():
        return False
    name = path.name.lower()
    if name in {"partial_layout.json", "segmented_partial_layout.txt", "probe_meta.json"}:
        return False
    if path.suffix.lower() in SCAN_EXTS:
        return True
    if os.access(path, os.X_OK):
        return True
    if path.stat().st_size <= 2 * 1024 * 1024:
        return True
    return False


def extract_strings_for_path(path: Path) -> list[str]:
    if path.suffix.lower() in TEXT_EXTS:
        try:
            data = path.read_bytes()[:256 * 1024]
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return lines[:4000]

    try:
        proc = subprocess.run(
            ["strings", "-a", "-n", "4", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        return lines[:4000]
    except Exception:
        return []


def surface_from_strings(strings: list[str], rel: str) -> list[str]:
    surfaces = set()
    lower_rel = rel.lower()
    if any(token in lower_rel for token in ("www", "web", "cgi", "rpc", "luci", "boafrm")):
        surfaces.add("web")
    lowered = [s.lower() for s in strings]
    if any(any(h in line for h in WEB_HINTS) for line in lowered):
        surfaces.add("web")
    if any(x in lower_rel for x in DAEMON_HINTS) or any(
        any(x in line for x in DAEMON_HINTS) for line in lowered
    ):
        surfaces.add("daemon")
    if any(any(h in line for h in PARSER_HINTS) for line in lowered):
        surfaces.add("parser")
    if not surfaces:
        surfaces.add("artifact")
    return sorted(surfaces)


def component_type(rel: str, strings: list[str], surfaces: list[str]) -> str:
    lower_rel = rel.lower()
    lowered = [s.lower() for s in strings]
    if "web" in surfaces:
        if any(tag in lower_rel for tag in ("cgi", "lua", "www", "boafrm", "rpc")):
            return "web"
        if any(any(h in line for h in WEB_HINTS) for line in lowered):
            return "web"
    if "daemon" in surfaces:
        return "daemon"
    if "parser" in surfaces:
        return "parser"
    return "artifact"


def input_hints(strings: list[str]) -> list[str]:
    joined = "\n".join(strings[:1000])
    hits = []
    for pattern in INPUT_HINT_PATTERNS:
        for hit in re.findall(pattern, joined, flags=re.IGNORECASE):
            if isinstance(hit, tuple):
                hit = hit[0]
            hit = str(hit).strip()
            if hit and len(hit) <= 120 and hit not in hits:
                hits.append(hit)
    return hits[:6]


def sink_hints(strings: list[str]) -> list[str]:
    sinks = detect_sinks(strings)
    out: list[str] = []
    for tier in ("critical", "strong", "weak"):
        for line in sinks.get(tier, []):
            if is_valid_sink(line, tier) and len(line) <= 180:
                out.append(line)
    for line in strings:
        lower = line.lower()
        if len(line) <= 180 and any(token in lower for token in MEMORY_HINTS | EXEC_HINTS):
            if line not in out:
                out.append(line)
    return out[:8]


def clean_endpoint_hints(strings: list[str]) -> list[str]:
    out = []
    for ep in extract_endpoints(strings):
        ep = str(ep).strip()
        if not ep or len(ep) > 120:
            continue
        if ep not in out:
            out.append(ep)
    return out[:6]


def parser_score(strings: list[str]) -> int:
    lowered = [s.lower() for s in strings]
    score = 0
    if any(any(h in line for h in PARSER_HINTS) for line in lowered):
        score += 2
    if any(any(h in line for h in MEMORY_HINTS) for line in lowered):
        score += 2
    if any(any(h in line for h in WEB_HINTS) for line in lowered):
        score += 1
    return score


def build_component(path: Path, root: Path, strings: list[str], evidence_source: str, web_bins: set[str], cgi_files: list[str]) -> dict | None:
    if not strings:
        return None

    rel = relpath(path, root)
    display_name = display_component_name(rel)
    endpoints = clean_endpoint_hints(strings)
    inputs = input_hints(strings)
    sinks = sink_hints(strings)
    surfaces = surface_from_strings(strings, rel)
    ctype = component_type(rel, strings, surfaces)

    web_hit = str(path) in web_bins or str(path) in cgi_files
    if web_hit and "web" not in surfaces:
        surfaces = sorted(set(surfaces) | {"web"})
        ctype = "web"

    if not endpoints and not inputs and not sinks and surfaces == ["artifact"]:
        if evidence_source in {"segmented", "probe"} and "segments/" in rel.replace("\\", "/"):
            label = "offset-carved payload"
            lower_rel = rel.lower()
            if lower_rel.endswith(".gz"):
                label = "embedded gzip payload"
            elif lower_rel.endswith(".xz"):
                label = "embedded xz payload"
            elif lower_rel.endswith(".lzma"):
                label = "embedded lzma payload"
            elif lower_rel.endswith(".7z"):
                label = "segmented bundle chunk"
            return {
                "component": display_name,
                "type": "parser",
                "input_hint": [label],
                "sink_hint": ["opaque parser target"],
                "surface": ["parser"],
                "partial_evidence_source": evidence_source,
                "endpoint_hints": [],
                "score": 4 if evidence_source == "probe" else 5,
            }
        return None

    lowered = [s.lower() for s in strings]
    score = 0
    if endpoints:
        score += 4
    if inputs:
        score += 3
    if sinks:
        score += 4
    if "web" in surfaces:
        score += 3
    if "daemon" in surfaces:
        score += 2
    score += parser_score(strings)
    if evidence_source in {"segmented", "probe"}:
        score += 1
    if any("/upload" in e or "/restore" in e or "multipart" in e for e in endpoints + inputs):
        score += 3
    if any(any(h in line for h in ("miniupnp", "soap", "upnp", "cwmp")) for line in lowered):
        score += 2

    return {
        "component": display_name,
        "type": ctype,
        "input_hint": inputs[:4] or endpoints[:4],
        "sink_hint": sinks[:4],
        "surface": surfaces,
        "partial_evidence_source": evidence_source,
        "endpoint_hints": endpoints[:6],
        "score": score,
    }


def discover_from_result(result_path: Path) -> dict:
    result = load_json(result_path)
    input_field = result.get("input")
    input_name = ""
    if isinstance(input_field, dict):
        input_name = str(input_field.get("filename") or input_field.get("path") or "")
    else:
        input_name = str(input_field or "")
    firmware = Path(input_name).stem
    if not firmware:
        run_id = str(result.get("run_id") or "")
        parts = Path(run_id).parts
        if len(parts) >= 2:
            firmware = f"{parts[-2]} / {parts[-1]}"
        else:
            firmware = run_id or result_path.name
    evidence_source = infer_evidence_source((result.get("analysis") or {}).get("system_path") or "", result)
    roots = candidate_roots(result)

    components: list[dict] = []
    seen_components = set()

    for root in roots:
        root_str = str(root)
        if root.is_dir():
            try:
                web_bins, cgi_files = scan_web_surface(root_str)
            except Exception:
                web_bins, cgi_files = set(), []
            walk_iter = os.walk(root, followlinks=True)
            for dirpath, _, filenames in walk_iter:
                for filename in filenames:
                    path = Path(dirpath) / filename
                    if not relevant_file(path):
                        continue
                    try:
                        if path.stat().st_size > 24 * 1024 * 1024:
                            continue
                    except Exception:
                        continue
                    strings = extract_strings_for_path(path)
                    comp = build_component(path, root, strings, evidence_source, web_bins, cgi_files)
                    if not comp:
                        continue
                    key = (comp["component"], tuple(comp["surface"]), tuple(comp["sink_hint"]))
                    if key in seen_components:
                        continue
                    seen_components.add(key)
                    components.append(comp)
        elif root.is_file():
            strings = extract_strings_for_path(root)
            comp = build_component(root, root.parent, strings, evidence_source, set(), [])
            if comp:
                key = (comp["component"], tuple(comp["surface"]), tuple(comp["sink_hint"]))
                if key not in seen_components:
                    seen_components.add(key)
                    components.append(comp)

    # Add synthetic container/probe candidates when the filesystem surface is sparse.
    for target in result.get("container_targets") or []:
        probe_bundle = target.get("probe_bundle") or {}
        hints = list(target.get("extraction_hints") or [])
        source_kind = str(target.get("source_kind") or "container")
        vendor_guess = str(target.get("vendor_guess") or "").strip()
        score = 3
        if "encrypted" in source_kind:
            score += 2
        if probe_bundle.get("candidate_count"):
            score += 2
        if hints:
            score += 1
        components.append({
            "component": target.get("name") or source_kind,
            "type": "parser",
            "input_hint": hints[:4] or [vendor_guess] if vendor_guess else [],
            "sink_hint": [probe_bundle.get("probe_type")] if probe_bundle.get("probe_type") else [],
            "surface": ["parser"],
            "partial_evidence_source": evidence_source,
            "endpoint_hints": [],
            "score": score,
        })

    components.sort(key=lambda row: (-row["score"], row["component"]))
    per_fw = components[:12]
    return {
        "firmware": firmware,
        "result_path": str(result_path),
        "analysis_root": str((result.get("analysis") or {}).get("system_path") or ""),
        "partial_evidence_source": evidence_source,
        "component_count": len(per_fw),
        "components": per_fw,
    }


def write_markdown(rows: list[dict], out_path: Path) -> None:
    lines = ["# Entrypoint Candidates", ""]
    for row in rows:
        lines.append(f"## {row['firmware']}")
        lines.append(f"- analysis_root: `{row['analysis_root']}`")
        lines.append(f"- partial_evidence_source: `{row['partial_evidence_source']}`")
        lines.append(f"- component_count: `{row['component_count']}`")
        lines.append("")
        for comp in row["components"]:
            lines.append(f"### {comp['component']}")
            lines.append(f"- type: `{comp['type']}`")
            lines.append(f"- surface: `{', '.join(comp['surface'])}`")
            lines.append(f"- input_hint: `{', '.join(comp['input_hint']) if comp['input_hint'] else 'n/a'}`")
            lines.append(f"- sink_hint: `{', '.join(comp['sink_hint']) if comp['sink_hint'] else 'n/a'}`")
            lines.append(f"- endpoint_hints: `{', '.join(comp['endpoint_hints']) if comp['endpoint_hints'] else 'n/a'}`")
            lines.append(f"- partial_evidence_source: `{comp['partial_evidence_source']}`")
            lines.append(f"- score: `{comp['score']}`")
            lines.append("")
    out_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", nargs="+", required=True, help="results.json files or ad hoc /tmp result bundles")
    ap.add_argument("--json-out", required=True)
    ap.add_argument("--markdown-out", required=True)
    args = ap.parse_args()

    rows = [discover_from_result(Path(p)) for p in args.results]
    Path(args.json_out).write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(rows, Path(args.markdown_out))
    summary = {row["firmware"]: row["component_count"] for row in rows}
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
