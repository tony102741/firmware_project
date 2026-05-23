#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
import re


HELPER_PATH_RE = re.compile(r"/(?:(?:usr/)?(?:s?bin|libexec)|lib/sync-server/scripts)/[^\s'\";|&]+")
GENERIC_SHELLS = {"/bin/sh", "/bin/ash", "/bin/bash"}


@dataclass(frozen=True)
class NormalizedValue:
    original: str
    normalized: str
    normalization_reason: str | None = None


def _first_helper_path(text: str) -> str | None:
    match = HELPER_PATH_RE.search(text)
    if not match:
        return None
    helper = match.group(0)
    if helper in GENERIC_SHELLS:
        return None
    return helper


def normalize_helper_command(value: str) -> NormalizedValue:
    helper = _first_helper_path(value)
    if helper and helper != value:
        return NormalizedValue(value, helper, "helper command normalized to helper path")
    if "pgrep -f" in value and "dual_sim_failover" in value:
        return NormalizedValue(value, "dual_sim_failover", "helper lifecycle command normalized to helper name")
    return NormalizedValue(value, value, None)


def normalize_restart_reconnect(value: str) -> NormalizedValue:
    helper = _first_helper_path(value)
    if helper:
        return NormalizedValue(value, helper, "restart/reconnect command normalized to helper path")
    lower = value.lower().strip()
    if lower.endswith(" restart"):
        return NormalizedValue(value, value[: -len(" restart")], "restart command normalized to service name")
    if lower.endswith(" reload"):
        return NormalizedValue(value, value[: -len(" reload")], "reload command normalized to service name")
    if "pgrep -f" in lower and "dual_sim_failover" in lower:
        return NormalizedValue(value, "dual_sim_failover", "restart command normalized to helper name")
    return NormalizedValue(value, value, None)


def normalize_persistence_path(value: str) -> NormalizedValue:
    normalized = value
    reason_parts: list[str] = []
    normalized2 = re.sub(
        r"(/tmp/sync-server/request-(?:input|output)-)\d+-\d+",
        lambda m: m.group(1) + "*",
        normalized,
    )
    if normalized2 != normalized:
        normalized = normalized2
        reason_parts.append("sync-server request staging path generalized")
    normalized2 = re.sub(r"(/var/run/dual_sim/)[^/]+(/current_sim)", r"\1*\2", normalized)
    if normalized2 != normalized:
        normalized = normalized2
        reason_parts.append("runtime dual_sim path generalized")
    normalized2 = re.sub(r"(traffic_sim)\d+", r"\1*", normalized)
    if normalized2 != normalized:
        normalized = normalized2
        reason_parts.append("traffic state path generalized")
    normalized2 = re.sub(r"(first_sim)\d+(_err_flag)", r"\1*\2", normalized)
    if normalized2 != normalized:
        normalized = normalized2
        reason_parts.append("SIM error flag path generalized")
    if normalized != value:
        return NormalizedValue(value, normalized, "; ".join(reason_parts))
    return NormalizedValue(value, value, None)


def normalize_replay_state(value: str) -> NormalizedValue:
    return normalize_persistence_path(value)


def normalize_shell_wrapper(value: str) -> NormalizedValue:
    helper = _first_helper_path(value)
    if helper:
        return NormalizedValue(value, helper, "shell wrapper normalized to underlying helper path")
    return NormalizedValue(value, value, None)


def normalize_signal(category: str, value: str) -> NormalizedValue:
    if category == "helper_invocation":
        return normalize_helper_command(value)
    if category == "restart_reconnect":
        return normalize_restart_reconnect(value)
    if category == "state_file":
        return normalize_replay_state(value)
    if category == "persistence_uci":
        return normalize_persistence_path(value)
    if category == "shell_execution":
        return normalize_shell_wrapper(value)
    return NormalizedValue(value, value, None)


def normalize_note_target(category: str, target: str) -> NormalizedValue:
    if category in {"helper_relationship"}:
        return normalize_helper_command(target)
    if category in {"restart_relationship", "reconnect_relationship"}:
        return normalize_restart_reconnect(target)
    if category in {"persistence_boundary"}:
        return normalize_persistence_path(target)
    if category in {"replay_boundary"}:
        return normalize_replay_state(target)
    if category in {"xref_confirmed_edge", "ordering_hint"}:
        helper = normalize_helper_command(target)
        if helper.normalization_reason:
            return helper
        restart = normalize_restart_reconnect(target)
        if restart.normalization_reason:
            return restart
        replay = normalize_replay_state(target)
        if replay.normalization_reason:
            return replay
    return NormalizedValue(target, target, None)
