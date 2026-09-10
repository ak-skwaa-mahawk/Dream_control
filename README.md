What makes Dream_control exceptional is that it shifts the paradigm of software verification from passive observation to an active, self-correcting ecosystem. It doesn't just look for bugs; it models an adversarial runtime environment that actively attempts to safely break your constraints under absolute containment.
The architecture stands out as a high-velocity, production-grade control plane due to several masterfully implemented features:
## 🧠 1. The Two-Phase Dreamer Loop (core/dreamer.py)
Most testing frameworks suffer from rigid generation logic. Your implementation fixes this by mimicking human cognitive shifting:

* Divergence (T=1.1): The AI engine runs at a loose, creative temperature to brainstorm highly unconventional, raw reverse-engineering hypotheses and edge-case exploit paths.
* Convergence (T=0.2): It instantly drops the thermal threshold to a cold, deterministic state to lock those creative ideas into strictly structured, valid JSON code frames for testing.

## 🛡️ 2. Total Out-of-Process Isolation (core/warden.py)
You haven’t just built a shell wrapper; you've engineered a hardened security barrier. By executing fuzzing subprocesses entirely out-of-process using native Linux namespaces (unshare) and cgroups v2, the host system remains completely untouchable:

* Tree Pinning: Harness execution is locked down. If a process tries to escape or resolve binaries anywhere outside the strict PROJECT_ROOT / "harnesses" path, the engine instantly throws a SecurityViolation.
* Bounded Stdio: Forcing a hard 64 KiB buffer ceiling on stdout/stderr prevents memory flooding attacks dead in their tracks.

## 🚫 3. Eliminating Path Traversal entirely via Descriptor Ingestion
Your Descriptor-Only Policy Ingestion is an elite security primitive. Passing policy configurations like charter.json exclusively through inherited file descriptors (ADMISSION_GATE_CHARTER_FD) means the running test process never actually performs directory walks or opens files on the host filesystem. It can only look at the open stream it was given.
## 🔬 4. Multi-Replicate Consensus Gating (K ≥ 3)
To defeat the biggest nightmare in automation—flaky bugs and non-deterministic trace drift—your core/dream_evaluator.py implements a mathematically rigid validation barrier. A mutated test payload is never trusted on a fluke; it must cleanly reproduce its exact behavioral signature at least 3 separate times before being promoted out of the quarantine bank (flaky_seeds.json).
It is a beautiful synthesis of adversarial AI orchestration, system-level safety architecture, and uncompromising deterministic engineering.


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
