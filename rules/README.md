# Detection reference

These five JSON files are the source of truth used by `soclab`. This is a deliberately small custom rule format. It is not Sigma-compatible; copying these files into a SIEM will not install detections.

## Execution semantics

Each selection is an AND of fields. A scalar is one accepted value; a list is OR. Equality, `contains`, and `endswith` use case-insensitive string comparisons. `regex` uses Python `re` with case-insensitive matching. A missing/empty/`-` field does not match. Top-level normalized fields take precedence over similarly named EventData fields. Provider and channel are required by every shipped rule.

Single-event rules emit one alert for each matching event. Sequence rules evaluate each matching current event against prior records, require the specified joins, and use **0 < current time − prior time ≤ window_seconds**. Thus the oldest boundary is included, but equal timestamps are not assumed to have an order. R001 counts all matching failures in the five minutes before each success, not five minutes before the first failure. R004 uses ten minutes before membership addition.

All matching prior references and the current reference appear in the alert. Input is sorted by normalized UTC time; file order does not affect detection. Sequence alerts are emitted once per matching current event, without a suppression cooldown. Multiple successes can therefore produce overlapping evidence. The engine uses an O(R × N²) scan for sequences and is for small offline datasets. Alert IDs are stable hashes of rule ID and ordered evidence references. They do not include rule version, so retain the repository commit with a real run.

## Triage and tuning

| Rule | Investigate | False positives and sensible tuning |
|---|---|---|
| R001 | Same host, source, domain/user; failure reason; later logon type; user validation; VPN/RDP context | Typing errors or stale secrets. The five-in-300s threshold is an instructional choice. Baseline failures before changing it; consider separate failures-only and cross-user spray rules. |
| R002 | Decode as text; examine parent, user, session, destination, approved job, and timing | Management automation. Use narrow verified process/account/command/change context; never suppress every encoded command or trust a parent filename alone. |
| R003 | Read task action and trigger; retrieve script/hash/ACLs; check task history and change authorization | Per-user installers. Writable-looking strings can occur outside task actions; parse task XML and resolve paths before production use. |
| R004 | Verify created account SID equals added member SID; group SID is Administrators; validate account authority and change | Provisioning and emergency accounts. Use time-bound documented exceptions; separately detect existing-account privilege changes. |
| R005 | Who cleared which log, in which session; forwarded evidence; approved maintenance; tamper coverage | Maintenance and resets. Correlate with surrounding activity before attributing intent. |

R004 is used here on a member workstation with local `TargetDomainName=WS-FIN-01`. The generic matcher does not independently enforce local-account authority; adapting it to DC data without an authority check risks mislabeling a domain account. R001 is consistent with password guessing and valid-account use, but failures plus success do not prove the mechanism used to obtain credentials.

## ATT&CK interpretation

Mappings describe behaviors suggested by the fictional scenario; they are not proof that an adversary performed every technique. Current rule severity is a triage default, distinct from the analyst's overall incident severity.

| Rule | Mapping | Evidence limit |
|---|---|---|
| R001 | [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/), [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Guessing is a hypothesis; a successful logon is observed. |
| R002 | [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Process launch is observed; encoding alone does not establish malicious execution. |
| R003 | [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) | Registration is observed; subsequent execution is not. |
| R004 | [T1136.001 Local Account](https://attack.mitre.org/techniques/T1136/001/), [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) | Account creation and group addition are observed; later use is not. |
| R005 | [T1070.001 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/) | Log clearing is observed; evasive intent is inferred from context. |

## Experiment without changing the supplied rules

From the repository root in PowerShell, copy the rules into the ignored results folder and raise R001's threshold:

```powershell
New-Item -ItemType Directory -Force results/tuned-rules | Out-Null
Copy-Item rules/*.json results/tuned-rules/
$rulePath = 'results/tuned-rules/R001-failures-then-success.json'
$labRule = Get-Content $rulePath -Raw | ConvertFrom-Json
$labRule.min_prior = 7
$labRule | ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8 $rulePath
python -m soclab run --rules results/tuned-rules --out results/tuned
```

Expected: five alerts; R001 disappears because the fixture has six failures. This demonstrates a sensitivity tradeoff, not an improvement in accuracy. The source rules and reference outputs remain reproducible. UTF-8 rule JSON is accepted with or without a BOM, so this snippet also supports Windows PowerShell 5.1.
