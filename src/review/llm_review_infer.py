"""
Run LLM-style review predictions over firmware review packets.

Supports two providers:

- heuristic: deterministic local baseline for end-to-end testing
- openai: Chat Completions API with structured JSON output
- hybrid: route only opaque or ambiguous cases to OpenAI and keep the rest local

Examples:
  python3 src/review/llm_review_infer.py \
      --packets research/review/llm/llm_review_packets.jsonl \
      --provider heuristic \
      --output research/review/llm/llm_review_predictions.jsonl

  python3 src/review/llm_review_infer.py \
      --packets research/review/llm/llm_review_packets.jsonl \
      --provider openai \
      --model gpt-5.2 \
      --output research/review/llm/llm_review_predictions.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable, List

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from review.llm_review import build_compact_packet


PROJECT_ROOT = SRC_ROOT.parent
PROJECT_KEY_FILES = (
    PROJECT_ROOT / ".env.local",
    PROJECT_ROOT / ".secrets" / "openai_api_key",
)


def load_jsonl(path: str | Path) -> List[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for idx, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                rows.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}: line {idx}: invalid JSON: {exc}") from exc
    return rows


def write_jsonl(path: str | Path, rows: Iterable[dict]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False))
            fh.write("\n")


def _load_project_api_key() -> str:
    env_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if env_key:
        return env_key

    for path in PROJECT_KEY_FILES:
        if not path.is_file():
            continue
        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            continue
        if path.name == ".env.local":
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                if key.strip() != "OPENAI_API_KEY":
                    continue
                value = value.strip().strip('"').strip("'")
                if value:
                    os.environ["OPENAI_API_KEY"] = value
                    return value
        else:
            os.environ["OPENAI_API_KEY"] = raw
            return raw
    return ""


def _safe_labels(packet: dict) -> dict:
    engine = packet.get("engine_state") or {}
    evidence = packet.get("evidence") or {}
    success_quality = engine.get("success_quality") or "unknown"
    probe_readiness = engine.get("probe_readiness") or "unknown"
    blob_family = engine.get("blob_family") or "none"
    web_surface_detected = bool(
        engine.get("web_surface_detected")
        or engine.get("analysis_mode") == "iot_web"
    )

    top_risk = "no-clear-rce"
    if success_quality == "blob-success" or probe_readiness in {
        "blob-ready",
        "decrypt-probe-ready",
        "scan-probe-ready",
        "bundle-probe-ready",
    }:
        top_risk = "container-analysis"
    else:
        for cand in evidence.get("top_candidates") or []:
            flow_type = str(cand.get("flow_type") or "").lower()
            sinks = [str(s).lower() for s in (cand.get("all_sinks") or [])]
            summary = str(cand.get("vuln_summary") or "").lower()
            if "overflow" in summary or "buffer_overflow" in flow_type:
                top_risk = "memory-corruption"
                break
            if "cmd_injection" in flow_type or ("command injection" in summary and any(
                tok in " ".join(sinks) for tok in ("os.execute", "/bin/sh", "session::system", "popen", "system", "exec")
            )):
                top_risk = "cmd-injection"
                break
        else:
            summary = engine.get("summary") or {}
            if summary.get("upgrade_findings"):
                top_risk = "upgrade-risk"
            elif summary.get("crypto_findings"):
                top_risk = "crypto-risk"
            elif evidence.get("container_targets"):
                top_risk = "container-analysis"

    if probe_readiness == "decrypt-probe-ready":
        best_next_action = "run-decrypt-probe"
    elif probe_readiness == "scan-probe-ready":
        best_next_action = "inspect-container-payload"
    elif probe_readiness == "bundle-probe-ready":
        best_next_action = "inspect-segmented-bundle"
    elif success_quality == "rootfs-success":
        best_next_action = "triage-top-candidates"
    elif success_quality == "blob-success":
        best_next_action = "expand-binary-signals"
    else:
        best_next_action = "review-artifacts"

    encrypted_container = blob_family == "tenda-openssl-container"

    if best_next_action == "run-decrypt-probe":
        next_actions = [
            "Run the generated OpenSSL probe script against the carved ciphertext.",
            "Check probe outputs for compressed rootfs or firmware magic after decryption.",
            "Trace vendor updater/GPL material for the exact KDF or passphrase source.",
        ]
    elif best_next_action == "inspect-container-payload":
        next_actions = [
            "Run the generated scan probe on the carved payload.",
            "Identify whether the payload starts with a secondary header or packed filesystem.",
            "Locate the vendor update parser that verifies or unwraps the cloud container.",
        ]
    elif best_next_action == "inspect-segmented-bundle":
        next_actions = [
            "Run the generated segmented bundle probe on the carved blob candidates.",
            "Look for filesystem magic, partition tables, or web-asset clusters in the decoded chunks.",
            "Prioritize decoded blobs that contain both HTTP/login strings and command sinks.",
        ]
    else:
        next_actions = [
            "Review the top candidate dossier paths and shortlist the most actionable lead.",
            "Validate the strongest source-to-sink chain before writing a vulnerability claim.",
            "Promote only candidates with concrete user-controlled input evidence.",
        ]

    triage_summary = (
        f"Current engine state is {success_quality} with {probe_readiness}. "
        f"Top risk family is {top_risk} based on the surfaced candidates and artifacts."
    )
    operator_summary = (
        f"{packet.get('firmware', {}).get('vendor')} {packet.get('firmware', {}).get('model')} "
        f"is currently classified as {success_quality}; next action is {best_next_action}."
    )

    return {
        "has_rootfs": success_quality == "rootfs-success",
        "has_web_ui": web_surface_detected,
        "artifact_kind": success_quality,
        "probe_readiness": probe_readiness,
        "blob_family": blob_family,
        "encrypted_container": encrypted_container,
        "best_next_action": best_next_action,
        "top_risk_family": top_risk,
        "next_actions": next_actions,
        "triage_summary": triage_summary,
        "operator_summary": operator_summary,
    }


def _json_schema() -> dict:
    return {
        "name": "firmware_review_prediction",
        "strict": True,
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "has_rootfs": {"type": "boolean"},
                "has_web_ui": {"type": "boolean"},
                "artifact_kind": {
                    "type": "string",
                    "enum": ["rootfs-success", "fallback-success", "blob-success", "unknown"],
                },
                "probe_readiness": {
                    "type": "string",
                    "enum": [
                        "rootfs-ready",
                        "fallback-ready",
                        "bundle-probe-ready",
                        "decrypt-probe-ready",
                        "scan-probe-ready",
                        "blob-ready",
                        "unknown",
                    ],
                },
                "blob_family": {
                    "type": "string",
                    "enum": [
                        "tp-link-segmented-bundle",
                        "mercusys-cloud-container",
                        "tenda-openssl-container",
                        "generic-container",
                        "generic-blob-signal",
                        "none",
                    ],
                },
                "encrypted_container": {"type": "boolean"},
                "best_next_action": {
                    "type": "string",
                    "enum": [
                        "triage-top-candidates",
                        "run-decrypt-probe",
                        "inspect-container-payload",
                        "inspect-segmented-bundle",
                        "expand-binary-signals",
                        "review-artifacts",
                    ],
                },
                "top_risk_family": {
                    "type": "string",
                    "enum": [
                        "cmd-injection",
                        "memory-corruption",
                        "upgrade-risk",
                        "crypto-risk",
                        "container-analysis",
                        "no-clear-rce",
                    ],
                },
                "next_actions": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 3,
                    "items": {"type": "string"},
                },
                "triage_summary": {"type": "string"},
                "operator_summary": {"type": "string"},
            },
            "required": [
                "has_rootfs",
                "has_web_ui",
                "artifact_kind",
                "probe_readiness",
                "blob_family",
                "encrypted_container",
                "best_next_action",
                "top_risk_family",
                "next_actions",
                "triage_summary",
                "operator_summary",
            ],
        },
    }


def _openai_messages(packet: dict) -> list[dict]:
    return [
        {
            "role": "developer",
            "content": (
                "You review firmware-analysis evidence packets. "
                "Use only the supplied evidence. "
                "Do not invent files, exploit chains, or endpoints. "
                "Return structured JSON that matches the schema exactly."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(packet, ensure_ascii=False, indent=2),
        },
    ]


def _should_use_openai(packet: dict) -> tuple[bool, str]:
    engine = packet.get("engine_state") or {}
    evidence = packet.get("evidence") or {}
    success_quality = engine.get("success_quality") or "unknown"
    probe_readiness = engine.get("probe_readiness") or "unknown"
    top_candidates = evidence.get("top_candidates") or []

    if probe_readiness in {"decrypt-probe-ready", "scan-probe-ready", "bundle-probe-ready"}:
        return True, f"opaque-artifact:{probe_readiness}"
    if success_quality not in {"rootfs-success", "fallback-success", "blob-success"}:
        return True, f"unclassified-success-quality:{success_quality}"
    if success_quality == "blob-success":
        return True, "blob-success"

    if len(top_candidates) >= 2:
        first = float(top_candidates[0].get("triage_score") or top_candidates[0].get("score") or 0)
        second = float(top_candidates[1].get("triage_score") or top_candidates[1].get("score") or 0)
        if first >= 30 and second >= 30 and abs(first - second) <= 2:
            return True, "tight-top-candidate-race"

    for cand in top_candidates[:3]:
        triage = float(cand.get("triage_score") or cand.get("score") or 0)
        if cand.get("web_exposed") and triage >= 35 and len(cand.get("missing_links") or []) >= 2:
            return True, "strong-web-candidate-with-gaps"

    return False, "clear-local-case"


def _extract_choice_text(response: dict) -> str:
    try:
        message = response["choices"][0]["message"]
    except Exception as exc:
        raise ValueError(f"unexpected OpenAI response shape: {response}") from exc

    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(item.get("text", ""))
        return "".join(parts).strip()
    raise ValueError(f"unexpected message content: {content!r}")


def _api_key_present() -> bool:
    return bool(_load_project_api_key())


def _openai_preflight(timeout: int) -> dict:
    payload = {
        "api_key_present": _api_key_present(),
        "network_ok": False,
        "api_ok": False,
        "detail": "",
    }
    if not payload["api_key_present"]:
        payload["detail"] = "OPENAI_API_KEY is not set"
        return payload

    req = urllib.request.Request(
        "https://api.openai.com/v1/models",
        headers={
            "Authorization": f"Bearer {_load_project_api_key()}",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        payload["network_ok"] = True
        payload["detail"] = f"OpenAI API HTTP {exc.code}: {detail}"
        return payload
    except urllib.error.URLError as exc:
        payload["detail"] = f"OpenAI API request failed: {exc}"
        return payload

    payload["network_ok"] = True
    payload["api_ok"] = True
    models = body.get("data") or []
    payload["detail"] = f"reachable ({len(models)} models visible)"
    return payload


def _call_openai(packet: dict, model: str, timeout: int) -> tuple[dict, dict]:
    api_key = _load_project_api_key()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")

    body = {
        "model": model,
        "temperature": 0,
        "messages": _openai_messages(packet),
        "response_format": {
            "type": "json_schema",
            "json_schema": _json_schema(),
        },
    }
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI API HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"OpenAI API request failed: {exc}") from exc

    text = _extract_choice_text(payload)
    try:
        prediction = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"model did not return valid JSON: {text}") from exc
    return prediction, payload


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--packets", required=True, help="JSONL emitted by src/review/llm_review.py --emit-corpus-packets")
    ap.add_argument("--provider", choices=("heuristic", "openai", "hybrid"), default="heuristic")
    ap.add_argument("--model", help="OpenAI model name when --provider=openai")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--output", required=True)
    ap.add_argument("--preflight", action="store_true", help="Check API key and OpenAI reachability before inference.")
    ap.add_argument(
        "--fallback-provider",
        choices=("heuristic", "fail"),
        default="heuristic",
        help="What to do if OpenAI preflight or request fails.",
    )
    ap.add_argument("--raw-dir", help="Optional directory for raw model responses or prompts.")
    args = ap.parse_args()

    packets = load_jsonl(args.packets)
    if args.limit:
        packets = packets[: args.limit]

    raw_dir = Path(args.raw_dir) if args.raw_dir else None
    if raw_dir:
        raw_dir.mkdir(parents=True, exist_ok=True)

    preflight = None
    openai_enabled = args.provider in {"openai", "hybrid"}
    if openai_enabled and args.preflight:
        preflight = _openai_preflight(min(args.timeout, 15))
        print(json.dumps({"preflight": preflight}, ensure_ascii=False, indent=2), flush=True)
        if not preflight.get("api_ok") and args.fallback_provider == "fail":
            raise SystemExit("OpenAI preflight failed and --fallback-provider=fail")
    elif openai_enabled:
        print(json.dumps({
            "preflight": {
                "api_key_present": _api_key_present(),
                "network_ok": None,
                "api_ok": None,
                "detail": "preflight skipped",
            }
        }, ensure_ascii=False, indent=2), flush=True)

    rows = []
    started = time.time()
    for idx, packet in enumerate(packets, 1):
        review_id = packet.get("review_id")
        print(f"[{idx}/{len(packets)}] {review_id}", flush=True)

        provider_used = args.provider
        route_reason = "forced-provider"
        if args.provider == "hybrid":
            use_openai, route_reason = _should_use_openai(packet)
            provider_used = "openai" if use_openai else "heuristic"
        if provider_used == "openai" and preflight and not preflight.get("api_ok"):
            if args.fallback_provider == "heuristic":
                provider_used = "heuristic"
                route_reason = f"preflight-fallback:{preflight.get('detail')}"
            else:
                raise RuntimeError(f"OpenAI preflight failed: {preflight.get('detail')}")

        if provider_used == "heuristic":
            predictions = _safe_labels(packet)
            raw = {
                "provider": "heuristic",
                "packet_id": review_id,
                "route_reason": route_reason,
            }
        else:
            if not args.model:
                raise SystemExit("--model is required when --provider=openai or --provider=hybrid")
            compact_packet = build_compact_packet(packet)
            try:
                predictions, raw = _call_openai(compact_packet, args.model, args.timeout)
            except Exception as exc:
                if args.fallback_provider != "heuristic":
                    raise
                provider_used = "heuristic"
                route_reason = f"request-fallback:{exc}"
                predictions = _safe_labels(packet)
                raw = {
                    "provider": "heuristic",
                    "packet_id": review_id,
                    "route_reason": route_reason,
                    "fallback_from": "openai",
                    "error": str(exc),
                }
            else:
                raw = {
                    "provider": "openai",
                    "route_reason": route_reason,
                    "request_packet": compact_packet,
                    "response": raw,
                }

        row = {
            "review_id": review_id,
            "provider": provider_used,
            "requested_provider": args.provider,
            "route_reason": route_reason,
            "model": args.model if provider_used == "openai" else "heuristic-baseline",
            "predictions": predictions,
        }
        rows.append(row)

        if raw_dir:
            out = raw_dir / f"{review_id}.json"
            out.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    write_jsonl(args.output, rows)
    print(json.dumps({
        "rows_written": len(rows),
        "provider": args.provider,
        "model": args.model if args.provider in {"openai", "hybrid"} else "heuristic-baseline",
        "openai_rows": sum(1 for r in rows if r["provider"] == "openai"),
        "heuristic_rows": sum(1 for r in rows if r["provider"] == "heuristic"),
        "fallback_provider": args.fallback_provider,
        "output": args.output,
        "elapsed_seconds": round(time.time() - started, 2),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
