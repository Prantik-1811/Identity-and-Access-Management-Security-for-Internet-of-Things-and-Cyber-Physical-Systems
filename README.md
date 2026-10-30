# Identity-and-Access-Management-Security-for-Internet-of-Things-and-Cyber-Physical-Systems
# IAM Security for IoT and Cyber-Physical Systems: Reference Prototype

Python reference prototype accompanying the paper **"Identity and Access Management Security for Internet of Things and Cyber-Physical Systems"** (MIT World Peace University, Pune).

The prototype is a small, in-memory rule engine that implements the decision path of a lifecycle-aware IAM architecture: identity checks, credential status, replay rejection, least-privilege permissions, context rules, constrained offline operation, audit logging, and an independent safety guard.

> **Scope warning:** This is a software-only research prototype, not a production IAM system. Credential validity and offline policy signatures are **Boolean flags** standing in for results a real cryptographic component would verify. There is no PKI, certificate handling, signature verification, remote attestation, networking, policy distribution, secure hardware, or physical controller integration. The prototype tests decision ordering and rule outcomes, not the strength of cryptography or the safety of real machinery.

## Decision rule

A request is allowed only when every predicate passes:

```
D = I ∧ C ∧ P ∧ X ∧ O ∧ S
```

| Symbol | Meaning |
|--------|---------|
| I | Verified, active identity |
| C | Valid credential and fresh request (nonce not replayed) |
| P | Matching action-resource permission for the role |
| X | Acceptable context (e.g. approved maintenance window) |
| O | Policy-valid operating mode (signed, fresh, low-risk when offline) |
| S | Positive result from the independent safety guard |

Any failure produces a denial and an audit record with the reason and policy version. IAM permission can never substitute for the safety result `S`.

## What is implemented

| Component | Paper reference | Code |
|-----------|-----------------|------|
| Authorize an access request | Algorithm 1 | `IAMEngine.authorize()` |
| Evaluate offline access | Algorithm 2 | `IAMEngine._offline_ok()` |
| Manage credential lifecycle | Algorithm 3 | `IAMEngine.lifecycle_event()` |
| 14 handcrafted test scenarios | Section VI | `build_scenarios()`, `run_scenarios()` |
| Latency microbenchmark | Section VI, Fig. 7 | `benchmark()` |

Check order in `authorize()`: identity, credential, nonce freshness, offline policy, permission, context, safety.

## Requirements

- Python 3.10 or newer (the paper's results were produced with Python 3.13.5)
- No third-party packages; standard library only

## Usage

Linux / macOS:

```bash
python3 iam_prototype.py
```

Windows (PowerShell):

```powershell
python iam_prototype.py
# or
py iam_prototype.py
```

Options:

```
--out DIR         output directory (default: iam_results)
--no-benchmark    run the 14 scenarios only
```

The script exits with a non-zero status if any scenario does not match its expected outcome.

If Windows shows garbled characters for `µ` in the console, run `$env:PYTHONUTF8=1` first. This affects display only.

## Outputs

Written to the output directory:

| File | Contents |
|------|----------|
| `test_results.csv` | Per-scenario expected vs observed decision and reason |
| `benchmark_results.csv` | Median, min and max per-request time for each batch size |
| `run_summary.json` | Python version, platform, pass counts, benchmark rows |

## Test scenarios

| # | Scenario | Expected | Reason |
|---|----------|----------|--------|
| 1 | Valid telemetry | allow | authorized |
| 2 | Unknown identity | deny | identity inactive |
| 3 | Revoked identity | deny | identity inactive |
| 4 | Invalid credential | deny | credential invalid |
| 5 | Unauthorized actuator action | deny | permission absent |
| 6 | Maintenance outside approved window | deny | context failure |
| 7 | Approved maintenance | allow | authorized |
| 8 | Replayed nonce | deny | replay or freshness failure |
| 9 | Offline telemetry (signed, fresh, low-risk) | allow | authorized |
| 10 | Offline configuration write | deny | offline policy failure |
| 11 | Stale policy cache (age over 300 s) | deny | offline policy failure |
| 12 | Unsafe actuation blocked by safety guard | deny | safety interlock |
| 13 | Invalid offline policy signature | deny | offline policy failure |
| 14 | Authorized diagnostics read | allow | authorized |

Four allow and ten deny outcomes. The imbalance is deliberate test design, not an estimate of real traffic.

## Microbenchmark

The benchmark times `authorize()` over batches of 100, 500, 1,000, 5,000 and 10,000 requests. Each batch size is run seven times with a fresh engine, and the median per-request time is reported. Requests are built before timing, so only the decision function is measured.

The paper reports medians of roughly 1.70 to 1.88 µs. Timings depend on the machine, Python version and load, so **your numbers will differ**; check `run_summary.json` for the platform that produced a given run. The benchmark covers only the in-memory rule path. It excludes cryptographic verification, network delay, persistent storage, embedded hardware and controller response time, so it says nothing about real IoT/CPS latency or scalability.

## Customizing the model

Roles, identities and low-risk offline actions are defined at the top of `iam_prototype.py`:

- `DEFAULT_ROLES`: role to set of `(action, resource)` pairs
- `DEFAULT_IDENTITIES`: device or user id to role and lifecycle status
- `LOW_RISK_ACTIONS`: actions permitted while offline
- `MAX_POLICY_AGE_S`: offline policy cache limit (300 s)

The 300-second limit is a test parameter, not a deployment recommendation. A real value would need a system-specific risk analysis.

## Known limitations

- No real cryptography, certificate issuance, hardware attestation or secure elements
- No network communication, distributed policy updates or persistent storage
- Passing handcrafted tests shows the code follows its specified rules, not that it resists unknown attacks
- No formal security properties established
- No comparative experiments against baselines yet

## Future work

- Real cryptographic verification and hardware-backed keys
- Persistent, distributed policy state
- Hardware-in-the-loop testbed compared against defined baselines under repeatable network and device workloads

## Repository structure

```
.
├── iam_prototype.py      # decision engine, scenarios, benchmark
├── iam_results/          # generated outputs (CSV, JSON)
└── README.md
```

## Authors

Prantik Chandra, Sami Shaikh, Sreeraj Rajesh, Dnyanesh Kokate
Department of Computer Science and Engineering, MIT WPU, Pune, India
Under the guidance of Dr. Vinayak Musale

## Citation

```
Prantik Chandra, Sami Shaikh, Sreeraj Rajesh, and Dnyanesh Kokate, "Identity and Access Management
Security for Internet of Things and Cyber-Physical Systems," MIT WPU, Pune, India, 2026.
```

## License

MIT License

Copyright (c) 2026 Prantik Chandra, Sami Shaikh, Sreeraj Rajesh, Dnyanesh Kokate

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
