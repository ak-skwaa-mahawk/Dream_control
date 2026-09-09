# Dream_control

Autonomous telemetry-guided fuzzing and verification control plane.

## Architecture

[Telemetry Ingestion]
(audit_log.jsonl) ──> core/telemetry_seed.py
│ (outliers)
▼
core/dream_scheduler.py ◄── [Promoted & Flaky Banks]
│ (plan)
▼
core/dreamer.py (Two-Phase: T=1.1 hypothesis -> T=0.2 JSON)
│ (Experiment)
▼
core/warden.py (Cell: unshare, cgroups v2, bounded stdio, tree-pinned)
│ (K >= 3 RawTraces)
▼
core/dream_evaluator.py (Signature corpus, novelty decay, K-replicate consensus)
│ (Verdict)
┌───────┴────────┐
▼                ▼
[Candidate Promoted]   [Flaky Quarantined]

## Security Invariants

1. **Cell Boundaries**: Subprocesses execute out-of-process via `core/warden.py` with sanitized environment primitives (`PATH`, `LANG`, `LC_ALL`, `PYTHONHASHSEED`), dedicated session creation (`start_new_session=True`), and `0700` cell directory permissions.
2. **Subtree Pinning**: Runners must reside strictly beneath `PROJECT_ROOT / "harnesses"`. Any binary resolution outside this tree raises `SecurityViolation`.
3. **Probe Integrity**: Probes emitted in `out.json` are filtered strictly against the harness's frozen `allowed_observables`. Non-whitelisted probes (e.g. `injected_fake_leak`) are dropped.
4. **Descriptor-Only Policy Ingestion**: Policy files (e.g. `charter.json`) are passed into harnesses exclusively through inherited file descriptors (`ADMISSION_GATE_CHARTER_FD`), eliminating arbitrary host filesystem traversal.
5. **Bounded Stdio**: Process stdout/stderr streams are polled and bounded up to `MAX_STDIO_BYTES` (64 KiB), preventing runaway memory exhaustion before ingest.
6. **Strict Codec**: `core/experiment_validator.py` enforces bounds and exact type checks (`int` rejects bool and float representations; strings are bounded by character length).
7. **Consensus Gating**: Candidates require $K \ge 3$ reproducible execution signatures to promote. Discrepant traces are quarantined to `flaky_seeds.json`.
