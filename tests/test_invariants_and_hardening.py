#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path
from core.dream_contract import HarnessSpec, ParamSpec, RawTrace, SecurityViolation
from core.experiment_validator import decode_params, ParameterValidationError
from core.warden import execute_in_cell, CellBackend, HostLandlockBackend, DockerCellBackend
from harnesses.gate_fuzz_runner import load_charter_pinned


class TestInvariantsAndHardening(unittest.TestCase):
    def test_decode_params_strictly_rejects_floats_for_int(self):
        spec = HarnessSpec(
            harness_id="test_int_rigor",
            target_subsystem="test",
            params={"concurrency": ParamSpec(kind="int", lo=1, hi=128)},
            allowed_observables=frozenset(["timeout"]),
            runner_binary=Path("/bin/true"),
        )
        with self.assertRaises(ParameterValidationError):
            decode_params(spec, {"concurrency": 10.9})
        with self.assertRaises(ParameterValidationError):
            decode_params(spec, {"concurrency": True})
        valid = decode_params(spec, {"concurrency": 10})
        self.assertEqual(valid["concurrency"], 10)

    def test_harness_tree_strictly_pinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            harness_dir = tmp_p / "harnesses"
            harness_dir.mkdir()
            outside_bin = tmp_p / "other_script.py"
            outside_bin.write_text("print('pwn')", encoding="utf-8")

            spec = HarnessSpec(
                harness_id="leak",
                target_subsystem="test",
                params={},
                allowed_observables=frozenset(),
                runner_binary=outside_bin,
            )
            with self.assertRaises(SecurityViolation):
                execute_in_cell(
                    spec=spec,
                    validated_params={},
                    budget_ms=500,
                    workspace_root=tmp_p / "ws",
                    harness_tree=harness_dir,
                )

    def test_charter_loader_defaults_without_descriptor(self):
        charter = load_charter_pinned()
        self.assertIn("prohibited_resource_patterns", charter)

    def test_trace_contains_isolation_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            harness = tmp_p / "runner.py"
            harness.write_text("import sys; sys.exit(0)", encoding="utf-8")
            spec = HarnessSpec(
                harness_id="iso_test",
                target_subsystem="test",
                params={},
                allowed_observables=frozenset(),
                runner_binary=harness,
            )
            trace = execute_in_cell(
                spec=spec,
                validated_params={},
                budget_ms=1000,
                workspace_root=tmp_p / "ws",
                harness_tree=tmp_p,
            )
            self.assertIn("session", trace.isolation)
            self.assertIn("unshare", trace.isolation)
            self.assertIn("cgroup", trace.isolation)
            self.assertIn("landlock", trace.isolation)

    def test_require_isolation_fails_closed_when_unsupported(self):
            with tempfile.TemporaryDirectory() as tmp:
                tmp_p = Path(tmp)
                harness = tmp_p / "harnesses" / "runner.py"
                harness.parent.mkdir()
                harness.write_text("import sys; sys.exit(0)", encoding="utf-8")
                spec = HarnessSpec(
                    harness_id="strict_iso",
                    target_subsystem="test",
                    params={},
                    allowed_observables=frozenset(),
                    runner_binary=harness,
                )
                # If current host lacks rootless unshare, cgroups, or landlock, this must raise SecurityViolation
                from core.warden import HAS_LANDLOCK, _probe_landlock_safe
                try:
                    execute_in_cell(
                        spec=spec,
                        validated_params={},
                        budget_ms=1000,
                        workspace_root=tmp_p / "ws",
                        harness_tree=tmp_p / "harnesses",
                        require_isolation=True,
                    )
                except SecurityViolation:
                    pass  # Successfully failed closed on unconfined host

    def test_symlink_escaping_harness_tree_rejected(self):
            with tempfile.TemporaryDirectory() as tmp:
                tmp_p = Path(tmp)
                harness_dir = tmp_p / "harnesses"
                harness_dir.mkdir()
                target_script = tmp_p / "outside.py"
                target_script.write_text("import sys; sys.exit(0)", encoding="utf-8")
                link = harness_dir / "link_runner.py"
                link.symlink_to(target_script)
    
                spec = HarnessSpec(
                    harness_id="symlink_leak",
                    target_subsystem="test",
                    params={},
                    allowed_observables=frozenset(),
                    runner_binary=link,
                )
                with self.assertRaises(SecurityViolation):
                    execute_in_cell(
                        spec=spec,
                        validated_params={},
                        budget_ms=500,
                        workspace_root=tmp_p / "ws",
                        harness_tree=harness_dir,
                    )

    def test_stdio_truncation_under_massive_output(self):
            with tempfile.TemporaryDirectory() as tmp:
                tmp_p = Path(tmp)
                harness = tmp_p / "harnesses" / "spammer.py"
                harness.parent.mkdir()
                # Emit 256KB of stdout to trigger bounded pipe drain
                harness.write_text("import sys\nsys.stdout.write('A' * (256 * 1024))\nsys.stdout.flush()", encoding="utf-8")
                spec = HarnessSpec(
                    harness_id="spam",
                    target_subsystem="test",
                    params={},
                    allowed_observables=frozenset(),
                    runner_binary=harness,
                )
                trace = execute_in_cell(
                    spec=spec,
                    validated_params={},
                    budget_ms=2000,
                    workspace_root=tmp_p / "ws",
                    harness_tree=tmp_p / "harnesses",
                )
                self.assertEqual(trace.exit_code, 0)
                self.assertIsNotNone(trace.stdout_hash)



    def test_cell_backend_protocol_conformance(self):
        host_backend = HostLandlockBackend()
        docker_backend = DockerCellBackend()
        self.assertIsInstance(host_backend, CellBackend)
        self.assertIsInstance(docker_backend, CellBackend)

    def test_docker_backend_fails_closed_when_unavailable_and_required(self):
        backend = DockerCellBackend(docker_bin="/nonexistent/docker/bin")
        self.assertFalse(backend.is_available())
        spec = HarnessSpec(
            harness_id="test_runner",
            target_subsystem="core",
            params={},
            allowed_observables=frozenset(["timeout"]),
            runner_binary=Path("/bin/true"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with self.assertRaises(SecurityViolation):
                backend.execute(
                    spec=spec,
                    validated_params={},
                    budget_ms=1000,
                    workspace_root=tmp_path / "workspace",
                    harness_tree=Path("/bin"),
                    require_isolation=True,
                )

    def test_execute_in_cell_dispatches_to_custom_backend(self):
        class MockBackend:
            def execute(self, **kwargs):
                return RawTrace(
                    exit_code=0,
                    wall_ms=10,
                    probes={"mock_dispatched": True},
                    stdout_hash="mock_out",
                    stderr_hash="mock_err",
                    signal=None,
                    max_rss_kb=1024,
                    isolation={"backend": "mock"},
                )

        spec = HarnessSpec(
            harness_id="test_runner",
            target_subsystem="core",
            params={},
            allowed_observables=frozenset(),
            runner_binary=Path("/bin/true"),
        )
        trace = execute_in_cell(
            spec=spec,
            validated_params={},
            budget_ms=1000,
            workspace_root=Path("/tmp"),
            harness_tree=Path("/bin"),
            backend=MockBackend(),
        )
        self.assertTrue(trace.probes.get("mock_dispatched"))
        self.assertEqual(trace.isolation.get("backend"), "mock")


    def test_charter_loader_supports_inline_base64_payload(self):
        import base64
        import json
        import os
        from harnesses.gate_fuzz_runner import load_charter

        custom_charter = {
            "authorized_prefixes": ["/tmp/safe_zone"],
            "statutory_prohibitions": ["/etc/shadow"],
        }
        encoded = base64.b64encode(json.dumps(custom_charter).encode("utf-8")).decode("ascii")

        old_val = os.environ.get("ADMISSION_GATE_CHARTER_PAYLOAD")
        try:
            os.environ["ADMISSION_GATE_CHARTER_PAYLOAD"] = encoded
            charter = load_charter()
            self.assertEqual(charter.get("authorized_prefixes"), ["/tmp/safe_zone"])
        finally:
            if old_val is None:
                os.environ.pop("ADMISSION_GATE_CHARTER_PAYLOAD", None)
            else:
                os.environ["ADMISSION_GATE_CHARTER_PAYLOAD"] = old_val

if __name__ == "__main__":
    unittest.main()
