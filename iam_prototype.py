#!/usr/bin/env python3
"""
Reference prototype: lifecycle-aware IAM decision engine for IoT / CPS.

Accompanies the paper "Identity and Access Management Security for
Internet of Things and Cyber-Physical Systems".

Scope (deliberately bounded, as in the paper):
  * In-memory rule engine only.
  * Credential validity and offline policy-signature validity are BOOLEAN
    FLAGS standing in for results a real cryptographic component would verify.
  * No PKI, certificate parsing, signature verification, attestation,
    network protocols, policy distribution, secure hardware, or real
    controller integration.

Decision rule (Eq. 1):  D = I ^ C ^ P ^ X ^ O ^ S
  I identity verified & active      C credential valid & request fresh
  P permission matches              X acceptable context
  O policy-valid operating mode     S independent safety result positive

Run:
    python3 iam_prototype.py                 # tests + benchmark, writes CSVs
    python3 iam_prototype.py --no-benchmark  # tests only
    python3 iam_prototype.py --out results   # choose output directory
"""

from __future__ import annotations

import argparse
import csv
import json
import platform
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

# Prototype test parameter, NOT a deployment recommendation (see paper §IV).
MAX_POLICY_AGE_S = 300

# Explicitly defined low-risk actions permitted while offline.
LOW_RISK_ACTIONS = frozenset({"publish_telemetry", "read_diagnostics"})

# Actions that drive physical actuators; gated by the independent safety guard.
ACTUATOR_ACTIONS = frozenset({"actuate"})

# Actions that modify configuration; require an approved maintenance context.
MAINTENANCE_WRITE_ACTIONS = frozenset({"write_config"})

# Role -> set of (action, resource) pairs.
DEFAULT_ROLES: dict[str, set[tuple[str, str]]] = {
    "sensor": {("publish_telemetry", "telemetry")},
    "maintenance": {
        ("read_diagnostics", "diagnostics"),
        ("write_config", "controller_config"),
    },
    "operator": {
        ("publish_telemetry", "telemetry"),
        ("actuate", "robot_arm"),
    },
}

# Identity id -> {"role": ..., "status": "active" | "revoked" | "retired"}
DEFAULT_IDENTITIES: dict[str, dict[str, str]] = {
    "sensor-01": {"role": "sensor", "status": "active"},
    "maint-01": {"role": "maintenance", "status": "active"},
    "ctrl-op-01": {"role": "operator", "status": "active"},
    "sensor-99": {"role": "sensor", "status": "revoked"},
}


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass(slots=True)
class Request:
    subject: str
    action: str
    resource: str
    nonce: Optional[str]
    credential_valid: bool = True          # stands in for crypto verification
    online: bool = True
    policy_signature_valid: bool = True    # stands in for signature check
    policy_age_s: float = 0.0
    maintenance_approved: bool = False     # context: approved service window
    safety_permits: bool = True            # simulated independent safety guard


@dataclass(slots=True)
class Decision:
    allowed: bool
    reason: str


@dataclass(slots=True)
class AuditRecord:
    subject: str
    action: str
    resource: str
    allowed: bool
    reason: str
    policy_version: str


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------

class IAMEngine:
    """In-memory decision engine implementing Algorithms 1, 2 and 3."""

    def __init__(
        self,
        identities: Optional[dict] = None,
        roles: Optional[dict] = None,
        policy_version: str = "v1",
        max_policy_age_s: float = MAX_POLICY_AGE_S,
        low_risk_actions: frozenset = LOW_RISK_ACTIONS,
    ) -> None:
        # Copy so each engine instance starts from a fresh state.
        src_ids = DEFAULT_IDENTITIES if identities is None else identities
        src_roles = DEFAULT_ROLES if roles is None else roles
        self.identities = {k: dict(v) for k, v in src_ids.items()}
        self.roles = {k: set(v) for k, v in src_roles.items()}
        self.seen_nonces: set[str] = set()
        self.audit_log: list[AuditRecord] = []
        self.policy_version = policy_version
        self.max_policy_age_s = max_policy_age_s
        self.low_risk_actions = low_risk_actions

    # ---- Algorithm 2: offline checks ------------------------------------
    def _offline_ok(self, r: Request) -> bool:
        if not r.policy_signature_valid:          # absent / unsigned policy
            return False
        if r.policy_age_s > self.max_policy_age_s:  # stale cache
            return False
        if r.action not in self.low_risk_actions:   # only low-risk actions
            return False
        return True

    # ---- Algorithm 1: authorize an access request -----------------------
    def authorize(self, r: Request) -> Decision:
        u = self.identities.get(r.subject)

        if u is None or u["status"] != "active":
            d = Decision(False, "identity inactive")
        elif not r.credential_valid:
            d = Decision(False, "credential invalid")
        elif r.nonce is None or r.nonce in self.seen_nonces:
            d = Decision(False, "replay or freshness failure")
        else:
            self.seen_nonces.add(r.nonce)
            if not r.online and not self._offline_ok(r):
                d = Decision(False, "offline policy failure")
            elif (r.action, r.resource) not in self.roles.get(u["role"], ()):
                d = Decision(False, "permission absent")
            elif r.action in MAINTENANCE_WRITE_ACTIONS and not r.maintenance_approved:
                d = Decision(False, "context failure")
            elif r.action in ACTUATOR_ACTIONS and not r.safety_permits:
                d = Decision(False, "safety interlock")
            else:
                d = Decision(True, "authorized")

        self.audit_log.append(
            AuditRecord(
                r.subject, r.action, r.resource,
                d.allowed, d.reason, self.policy_version,
            )
        )
        return d

    # ---- Algorithm 3: credential lifecycle ------------------------------
    def lifecycle_event(
        self, device: str, event: str, role: Optional[str] = None
    ) -> str:
        """Apply enroll / rotate / compromise / retire; returns new status.

        Unknown events are rejected and the previous state is retained.
        Every outcome is audited. Credential material itself is out of scope
        (the prototype tracks status only).
        """
        status = self.identities.get(device, {}).get("status", "absent")
        if event == "enroll":
            if role is None or role not in self.roles:
                outcome = "rejected: unknown role"
            else:
                self.identities[device] = {"role": role, "status": "active"}
                outcome = "enrolled"
        elif event == "rotate":
            # Replacement issued and confirmed before the old one is revoked;
            # status stays active throughout (safe-overlap model).
            outcome = "rotated" if device in self.identities else "rejected: unknown device"
        elif event == "compromise":
            if device in self.identities:
                self.identities[device]["status"] = "revoked"
                outcome = "revoked"
            else:
                outcome = "rejected: unknown device"
        elif event == "retire":
            if device in self.identities:
                self.identities[device]["status"] = "retired"
                outcome = "retired"
            else:
                outcome = "rejected: unknown device"
        else:
            outcome = "rejected: unknown event"

        self.audit_log.append(
            AuditRecord(device, f"lifecycle:{event}", "identity_registry",
                        not outcome.startswith("rejected"), outcome,
                        self.policy_version)
        )
        return self.identities.get(device, {}).get("status", status)


# --------------------------------------------------------------------------
# Scenarios (14 handcrafted cases)
# --------------------------------------------------------------------------

@dataclass
class Scenario:
    name: str
    request: Request
    expected_allow: bool
    expected_reason: str
    setup: list = field(default_factory=list)  # requests run first (e.g. replay)


def build_scenarios() -> list[Scenario]:
    return [
        Scenario("valid_telemetry",
                 Request("sensor-01", "publish_telemetry", "telemetry", "n01"),
                 True, "authorized"),
        Scenario("unknown_identity",
                 Request("ghost-00", "publish_telemetry", "telemetry", "n02"),
                 False, "identity inactive"),
        Scenario("revoked_identity",
                 Request("sensor-99", "publish_telemetry", "telemetry", "n03"),
                 False, "identity inactive"),
        Scenario("invalid_credential",
                 Request("sensor-01", "publish_telemetry", "telemetry", "n04",
                         credential_valid=False),
                 False, "credential invalid"),
        Scenario("unauthorized_actuator_action",
                 Request("sensor-01", "actuate", "robot_arm", "n05"),
                 False, "permission absent"),
        Scenario("maintenance_outside_window",
                 Request("maint-01", "write_config", "controller_config", "n06",
                         maintenance_approved=False),
                 False, "context failure"),
        Scenario("approved_maintenance",
                 Request("maint-01", "write_config", "controller_config", "n07",
                         maintenance_approved=True),
                 True, "authorized"),
        Scenario("replayed_nonce",
                 Request("sensor-01", "publish_telemetry", "telemetry", "n08"),
                 False, "replay or freshness failure",
                 setup=[Request("sensor-01", "publish_telemetry", "telemetry", "n08")]),
        Scenario("offline_telemetry_permitted",
                 Request("sensor-01", "publish_telemetry", "telemetry", "n09",
                         online=False, policy_signature_valid=True,
                         policy_age_s=120),
                 True, "authorized"),
        Scenario("offline_config_write_denied",
                 Request("maint-01", "write_config", "controller_config", "n10",
                         online=False, policy_signature_valid=True,
                         policy_age_s=120, maintenance_approved=True),
                 False, "offline policy failure"),
        Scenario("stale_policy_cache",
                 Request("sensor-01", "publish_telemetry", "telemetry", "n11",
                         online=False, policy_signature_valid=True,
                         policy_age_s=MAX_POLICY_AGE_S + 1),
                 False, "offline policy failure"),
        Scenario("blocked_unsafe_actuation",
                 Request("ctrl-op-01", "actuate", "robot_arm", "n12",
                         safety_permits=False),
                 False, "safety interlock"),
        Scenario("invalid_offline_policy_signature",
                 Request("sensor-01", "publish_telemetry", "telemetry", "n13",
                         online=False, policy_signature_valid=False,
                         policy_age_s=10),
                 False, "offline policy failure"),
        Scenario("authorized_diagnostics_read",
                 Request("maint-01", "read_diagnostics", "diagnostics", "n14"),
                 True, "authorized"),
    ]


def run_scenarios() -> list[dict]:
    rows = []
    for i, sc in enumerate(build_scenarios(), start=1):
        engine = IAMEngine()               # fresh state per scenario
        for pre in sc.setup:
            engine.authorize(pre)
        d = engine.authorize(sc.request)
        passed = (d.allowed == sc.expected_allow) and (d.reason == sc.expected_reason)
        rows.append({
            "id": i,
            "scenario": sc.name,
            "expected": "allow" if sc.expected_allow else "deny",
            "expected_reason": sc.expected_reason,
            "observed": "allow" if d.allowed else "deny",
            "observed_reason": d.reason,
            "passed": passed,
        })
    return rows


# --------------------------------------------------------------------------
# Microbenchmark
# --------------------------------------------------------------------------

BATCH_SIZES = (100, 500, 1_000, 5_000, 10_000)
REPETITIONS = 7


def benchmark() -> list[dict]:
    """Median per-request time (microseconds) of IAMEngine.authorize().

    Each batch size is run REPETITIONS times with a fresh engine. Requests
    (with unique nonces) are built before timing so only authorize() is
    measured. Excludes crypto, networking and device hardware.
    """
    rows = []
    for n in BATCH_SIZES:
        per_request_us = []
        for rep in range(REPETITIONS):
            engine = IAMEngine()
            reqs = [
                Request("sensor-01", "publish_telemetry", "telemetry", f"b{n}-{rep}-{k}")
                for k in range(n)
            ]
            authorize = engine.authorize
            t0 = time.perf_counter_ns()
            for r in reqs:
                authorize(r)
            t1 = time.perf_counter_ns()
            per_request_us.append((t1 - t0) / n / 1_000.0)
        rows.append({
            "batch_size": n,
            "repetitions": REPETITIONS,
            "median_us_per_request": round(statistics.median(per_request_us), 3),
            "min_us": round(min(per_request_us), 3),
            "max_us": round(max(per_request_us), 3),
        })
    return rows


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="iam_results", help="output directory")
    ap.add_argument("--no-benchmark", action="store_true", help="skip microbenchmark")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # --- scenario tests ---
    results = run_scenarios()
    write_csv(out / "test_results.csv", results)
    n_pass = sum(r["passed"] for r in results)
    n_allow = sum(r["observed"] == "allow" for r in results)

    print(f"{'#':>2}  {'scenario':<34} {'expected':<8} {'observed':<8} {'reason':<28} ok")
    for r in results:
        print(f"{r['id']:>2}  {r['scenario']:<34} {r['expected']:<8} "
              f"{r['observed']:<8} {r['observed_reason']:<28} "
              f"{'PASS' if r['passed'] else 'FAIL'}")
    print(f"\n{n_pass}/{len(results)} scenarios matched expected outcomes "
          f"({n_allow} allow, {len(results) - n_allow} deny)")

    summary = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "scenarios_total": len(results),
        "scenarios_passed": n_pass,
        "allow_decisions": n_allow,
        "deny_decisions": len(results) - n_allow,
        "max_policy_age_s": MAX_POLICY_AGE_S,
    }

    # --- microbenchmark ---
    if not args.no_benchmark:
        bench = benchmark()
        write_csv(out / "benchmark_results.csv", bench)
        summary["benchmark"] = bench
        print("\nMicrobenchmark (median per-request authorize() time):")
        for b in bench:
            print(f"  batch {b['batch_size']:>6}: {b['median_us_per_request']:.3f} µs")
        print("Note: in-memory rule path only; excludes crypto, network, hardware.")

    (out / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nOutputs written to: {out.resolve()}")
    return 0 if n_pass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
