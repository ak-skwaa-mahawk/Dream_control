#!/usr/bin/env python3
import re
import sys
from dataclasses import dataclass, field
from typing import List, Dict, Any

DEVICE_CODE_RE = re.compile(r"\b[A-Z0-9]{4}-[A-Z0-9]{4}\b", re.IGNORECASE)
GITHUB_DEVICE_URL_RE = re.compile(r"github\.com/login/device", re.IGNORECASE)
OAUTH_FLOW_TERMS = [
    "login/device",
    "device_code",
    "enter the code",
    "enter that code",
    "github authorization",
    "sign in the github cli on my computer",
]

VALID_FRAME_SIZE = 424

@dataclass
class ThreatReport:
    is_safe: bool = True
    violations: List[str] = field(default_factory=list)
    risk_score: int = 0

def scan_text_payload(text: str) -> ThreatReport:
    report = ThreatReport()
    lower_text = text.lower()

    has_device_url = bool(GITHUB_DEVICE_URL_RE.search(text))
    has_user_code = bool(DEVICE_CODE_RE.search(text))
    flow_matches = [term for term in OAUTH_FLOW_TERMS if term in lower_text]

    if has_device_url or (has_user_code and flow_matches):
        report.is_safe = False
        report.risk_score += 90
        report.violations.append(
            "CRITICAL: OAuth Device Authorization Grant detected (RFC 8628). "
            "Credential hijacking / browser delegation attempt."
        )

    token_phish_patterns = [
        r"ghp_[a-zA-Z0-9]{36}",
        r"github_pat_[a-zA-Z0-9_]{82}",
        r"BEGIN PRIVATE KEY",
    ]
    for pattern in token_phish_patterns:
        if re.search(pattern, text):
            report.is_safe = False
            report.risk_score += 100
            report.violations.append(
                f"CRITICAL: Raw credential or private key material found: {pattern}"
            )

    return report

def validate_frame_specification(frame_size: int, seq_id_bits: int) -> ThreatReport:
    report = ThreatReport()

    if frame_size != VALID_FRAME_SIZE:
        report.is_safe = False
        report.risk_score += 40
        report.violations.append(
            f"PROTOCOL_VIOLATION: Frame size {frame_size}B does not match "
            f"canonical specification ({VALID_FRAME_SIZE}B at offset 0x0400)."
        )

    if seq_id_bits != 32:
        report.is_safe = False
        report.risk_score += 30
        report.violations.append(
            f"PROTOCOL_VIOLATION: Sequence ID counter is {seq_id_bits}-bit. Expected 32-bit."
        )

    return report

def scan_patch_diff(diff_content: str) -> ThreatReport:
    report = ThreatReport()
    suspicious_patterns = [
        (r"permissions:\s*write-all", "Elevation: Workflow requests write-all permissions"),
        (r"pull_request_target", "Attack Vector: pull_request_target allows secret leakage from forks"),
        (r"curl\s+.*\|\s*(?:bash|sh)", "Remote Execution: Pipe remote script to shell"),
    ]
    for pattern, desc in suspicious_patterns:
        if re.search(pattern, diff_content):
            report.is_safe = False
            report.risk_score += 50
            report.violations.append(f"CI_TAMPER_WARNING: {desc}")

    return report

def inspect_ingress(source: str, content: str, frame_meta: Dict[str, Any] = None) -> bool:
    combined_report = ThreatReport()
    t_rep = scan_text_payload(content)
    combined_report.violations.extend(t_rep.violations)
    combined_report.risk_score += t_rep.risk_score

    if "diff --git" in content or "--- a/" in content:
        d_rep = scan_patch_diff(content)
        combined_report.violations.extend(d_rep.violations)
        combined_report.risk_score += d_rep.risk_score

    if frame_meta:
        f_rep = validate_frame_specification(
            frame_meta.get("frame_size", VALID_FRAME_SIZE),
            frame_meta.get("seq_id_bits", 32)
        )
        combined_report.violations.extend(f_rep.violations)
        combined_report.risk_score += f_rep.risk_score

    combined_report.is_safe = (combined_report.risk_score == 0)

    print(f"=== Sovereign Ingress Gate Scan [{source}] ===")
    if combined_report.is_safe:
        print("[+] STATUS: ADMITTED")
        return True
    else:
        print(f"[-] STATUS: BLOCKED (Risk Score: {combined_report.risk_score}/100)")
        for v in combined_report.violations:
            print(f"    ! {v}")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        adv = "open https://github.com/login/device and enter code E003-0A0C"
        assert inspect_ingress("Adversarial Ingress", adv) == False
        assert inspect_ingress("Frame Ingress", "", {"frame_size": 408, "seq_id_bits": 64}) == False
        assert inspect_ingress("Clean PR", "feat: add RFC 8032 test vectors", {"frame_size": 424, "seq_id_bits": 32}) == True
        print("\n[+] All firewall test vectors verified and passing.")
        sys.exit(0)
