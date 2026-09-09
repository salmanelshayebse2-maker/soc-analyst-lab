# Validation record

Local validation date: **2026-09-09**. Environment: Windows, **Python 3.12.14**. The repository has no third-party runtime or test dependencies.

## Reproduce

Run from the repository root:

```powershell
python -m soclab verify
python -m unittest discover -s tests -v
python -m soclab run
```

Expected: one matching evidence hash, **28 passing tests**, **141 parsed records**, and **six alerts**. Captured local command output is included in [test-run.txt](../sample-output/test-run.txt). The committed JSON, CSV, JSONL, and Markdown outputs were regenerated from the final fixture and compared against a fresh run.

## Coverage

| Area | What was checked |
|---|---|
| Fixture | Exact count, deterministic regeneration, SHA-256, deliberate tamper rejection |
| Alert expectations | Exact rule/evidence pairs, stable ordering, six unresolved alerts; benign baseline has only its intended encoded-command alert |
| Authentication | Five-versus-four threshold, required success, 300-versus-301-second boundary, same/future timestamps excluded, domain/user/IP/host separation, missing join fields, case-insensitive account identity, local logon exclusion |
| PowerShell | Flag variants, negative controls, image restriction, invalid Base64, text-only decoding |
| Scheduled task | Public-path match, Program Files negative control, missing TaskContent |
| Account changes | Created/member SID match, correct group SID, host separation, ten-minute boundary, order |
| Parser | Windows namespaces, 1102 UserData, single-event export, malformed XML, missing System, DTD rejection, duplicate identities, timezone normalization |
| Outputs | Deterministic regeneration, JSON validity, 141 JSONL records, 142 CSV rows including header |
| CLI | Full run, verify, inspect/decode, missing file/reference errors, empty input rejection |

Subtests exercise multiple values within several test methods; “28” is the unittest test-method count, not a count of every individual assertion. The suite validates this fixture and defined rule semantics, not all Windows export variants or attacks.

## Additional delivery checks

The interview's in-memory threshold change was run: raising R001 from five required failures to seven yields **five alerts**, with R001 absent. The normal quick start and delivery launcher were executed. Committed sample-output files match a fresh run. Local Markdown links and shipped JSON rule syntax were checked. Python source was compiled successfully.

## Not claimed

No hosted GitHub Actions run, native EVTX ingestion, SIEM rule compilation/deployment, real Windows audit-policy configuration, live attack execution, containment, or cross-platform runtime test was performed. The workflow defines a Windows/Linux and Python 3.10/3.12 matrix for future repository runs. Microsoft/Sysmon event meanings were checked against primary documentation; the synthetic fixture intentionally omits many real event fields.
