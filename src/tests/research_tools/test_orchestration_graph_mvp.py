#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.research_tools.orch_graph_normalization import normalize_signal
from src.research_tools.orchestration_graph_mvp import (
    build_output,
    classify_signals,
    collect_exports,
    collect_imports,
    collect_strings,
    load_notes,
    normalize_notes,
)
from src.research_tools.orchestration_note_drafter import draft_from_markdown


class NormalizationTests(unittest.TestCase):
    def test_switch_sim_slot_helper_normalization(self) -> None:
        normalized = normalize_signal("helper_invocation", "/usr/bin/switch_sim_slot %s timing start")
        self.assertEqual(normalized.normalized, "/usr/bin/switch_sim_slot")

    def test_dual_sim_failover_lifecycle_normalization(self) -> None:
        normalized = normalize_signal("restart_reconnect", "kill -15 $(pgrep -f dual_sim_failover)")
        self.assertEqual(normalized.normalized, "dual_sim_failover")

    def test_kmwan_restart_normalization(self) -> None:
        normalized = normalize_signal("restart_reconnect", "kmwan restart")
        self.assertEqual(normalized.normalized, "kmwan")

    def test_syncserver_request_input_normalization(self) -> None:
        normalized = normalize_signal("state_file", "/tmp/sync-server/request-input-123-456")
        self.assertEqual(normalized.normalized, "/tmp/sync-server/request-input-*")

    def test_syncserver_request_output_normalization(self) -> None:
        normalized = normalize_signal("state_file", "/tmp/sync-server/request-output-123-456")
        self.assertEqual(normalized.normalized, "/tmp/sync-server/request-output-*")


class RawTypingTests(unittest.TestCase):
    def _labels_by_type(self, value: str) -> dict[str, set[str]]:
        signals = classify_signals([value], [], {})
        output = build_output(Path("dummy.bin"), "unit", signals, [], [], {}, [])
        by_type: dict[str, set[str]] = {}
        for node in output["nodes"]:
            by_type.setdefault(node["node_type"], set()).add(node["label"])
        return by_type

    def test_projection_phrase_prefers_downstream(self) -> None:
        by_type = self._labels_by_type("Sync configuration to network...")
        self.assertIn("Sync configuration to network...", by_type.get("downstream_mutation_endpoint", set()))
        self.assertNotIn("Sync configuration to network...", by_type.get("persistence_object", set()))

    def test_activation_phrase_keeps_activation_endpoint(self) -> None:
        by_type = self._labels_by_type("Start_dial")
        self.assertIn("Start_dial", by_type.get("activation_endpoint", set()))

    def test_glmodem_network_sim_persistence_preserved(self) -> None:
        by_type = self._labels_by_type("glmodem.network_sim%d")
        self.assertIn("glmodem.network_sim%d", by_type.get("persistence_object", set()))

    def test_network_iccid_persistence_and_context_preserved(self) -> None:
        by_type = self._labels_by_type("network.%s.iccid")
        self.assertIn("network.%s.iccid", by_type.get("persistence_object", set()))
        self.assertIn("network.%s.iccid", by_type.get("context_only", set()))

    def test_syncserver_helper_path_prefers_semantic_helper(self) -> None:
        by_type = self._labels_by_type("/lib/sync-server/scripts/request")
        self.assertIn("/lib/sync-server/scripts/request", by_type.get("semantic_helper", set()))
        self.assertNotIn("/lib/sync-server/scripts/request", by_type.get("persistence_object", set()))

    def test_syncserver_request_input_prefers_temporary_state(self) -> None:
        by_type = self._labels_by_type("/tmp/sync-server/request-input-123-456")
        self.assertIn("/tmp/sync-server/request-input-*", by_type.get("temporary_state_object", set()))
        self.assertNotIn("/tmp/sync-server/request-input-*", by_type.get("persistence_object", set()))

    def test_syncserver_request_output_prefers_temporary_state(self) -> None:
        by_type = self._labels_by_type("/tmp/sync-server/request-output-123-456")
        self.assertIn("/tmp/sync-server/request-output-*", by_type.get("temporary_state_object", set()))
        self.assertNotIn("/tmp/sync-server/request-output-*", by_type.get("persistence_object", set()))

    def test_syncserver_onemesh_client_list_prefers_temporary_state(self) -> None:
        by_type = self._labels_by_type("/tmp/sync-server/onemesh_client_list")
        self.assertIn("/tmp/sync-server/onemesh_client_list", by_type.get("temporary_state_object", set()))
        self.assertNotIn("/tmp/sync-server/onemesh_client_list", by_type.get("persistence_object", set()))

    def test_unrelated_tmp_path_not_over_promoted(self) -> None:
        by_type = self._labels_by_type("/tmp/foo")
        self.assertIn("/tmp/foo", by_type.get("temporary_state_object", set()))
        self.assertNotIn("/tmp/foo", by_type.get("semantic_helper", set()))

    def test_clientmgmt_history_list_prefers_persistence_object(self) -> None:
        by_type = self._labels_by_type("history_list")
        self.assertIn("history_list", by_type.get("persistence_object", set()))

    def test_clientmgmt_var_state_fing_prefers_temporary_state(self) -> None:
        by_type = self._labels_by_type("/var/state/fing")
        self.assertIn("/var/state/fing", by_type.get("temporary_state_object", set()))

    def test_clientmgmt_saveconfig_prefers_activation_endpoint(self) -> None:
        by_type = self._labels_by_type("saveconfig")
        self.assertIn("saveconfig", by_type.get("activation_endpoint", set()))
        self.assertNotIn("saveconfig", by_type.get("persistence_object", set()))

    def test_clientmgmt_uci_commit_remains_persistence_primitive(self) -> None:
        by_type = self._labels_by_type("uci_commit")
        self.assertIn("uci_commit", by_type.get("persistence_object", set()))

    def test_unrelated_history_like_string_not_over_promoted(self) -> None:
        by_type = self._labels_by_type("history_buffer")
        self.assertNotIn("history_buffer", by_type.get("persistence_object", set()))


class GlModemIntegrationTests(unittest.TestCase):
    def test_glmodem_drafted_notes_do_not_generate_hard_conflicts(self) -> None:
        binary = REPO_ROOT / "ghidra_targets/GL-X3000/rootfs/usr/bin/gl_modem"
        if not binary.is_file():
            self.skipTest(f"missing binary fixture: {binary}")

        markdown_paths = [
            REPO_ROOT / "research/regeneration/full_corpus_20260508/families/GL-X3000/glmodem_native_staging_analysis.md",
            REPO_ROOT / "research/regeneration/full_corpus_20260508/families/GL-X3000/glmodem_orchestration_candidates.md",
            REPO_ROOT / "research/regeneration/full_corpus_20260508/families/GL-X3000/glmodem_downstream_mutation_paths.md",
        ]
        missing_markdown = [path for path in markdown_paths if not path.is_file()]
        if missing_markdown:
            self.skipTest(f"missing markdown fixtures: {', '.join(str(path) for path in missing_markdown)}")
        combined = "\n".join(path.read_text(encoding="utf-8") for path in markdown_paths)
        drafted = draft_from_markdown(combined, "GL-X3000-gl_modem-test")
        warnings: list[str] = []
        notes = normalize_notes(drafted, warnings)

        strings = collect_strings(binary, warnings)
        imports = collect_imports(binary, warnings)
        exports = collect_exports(binary, warnings)
        signals = classify_signals(strings, imports, notes)
        output = build_output(binary, "GL-X3000-gl_modem-test", signals, imports, exports, notes, warnings)

        self.assertFalse(
            any("hard node type conflict" in warning for warning in warnings),
            f"unexpected hard conflict warnings: {warnings}",
        )
        labels_by_type: dict[str, set[str]] = {}
        for node in output["nodes"]:
            labels_by_type.setdefault(node["node_type"], set()).add(node["label"])
        self.assertIn(
            "Sync configuration to network...",
            labels_by_type.get("downstream_mutation_endpoint", set()),
        )
        self.assertIn(
            "glmodem.network_sim%d",
            labels_by_type.get("persistence_object", set()),
        )
        self.assertIn(
            "network.%s.iccid",
            labels_by_type.get("persistence_object", set()),
        )


if __name__ == "__main__":
    unittest.main()
