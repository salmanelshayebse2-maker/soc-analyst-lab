# Eight-minute interview demonstration

## Before the interview

Open a terminal in the repository root and run the README quick start. Keep the README, generated summary, R001/R004 JSON rules, and incident report in editor tabs. Use a readable font and avoid scrolling through the entire XML. Keep `sample-output/` available if Python is unavailable. Everything runs offline.

## 0:00–0:45 — State the scope honestly

Say:

> “This is an offline SOC investigation using synthetic Windows Security and Sysmon evidence. I can reproduce five detection rules, triage six alerts, and explain the evidence behind an escalation. One alert is approved automation, so matching a rule is only the start of the investigation.”

## 0:45–1:30 — Reproduce and establish integrity

```powershell
python -m soclab verify
python -m unittest discover -s tests -v
python -m soclab run
```

Point to the hash verification, 28 passing tests, 141 records, and six alerts. Open `results/summary.md`.

Say:

> “The manifest detects changes to this evidence file. It is stored alongside the fixture, so it is not independent proof of authenticity. The tests check correlation boundaries and negative cases, not just whether code runs.”

## 1:30–2:30 — Explain the authentication detection

Open `rules/R001-failures-then-success.json`, then run:

```powershell
python -m soclab show 'WS-FIN-01|Security|1306'
```

Point to user `j.morgan`, source `192.0.2.44`, `LogonType=10`, and `TargetLogonId=0x9f2a`. Explain that six failures occurred from 10:14:00 to 10:14:50 and success at 10:15:20. The rule requires at least five prior failures within 300 seconds with the same host/domain/user/source. It allows types 3 and 10 because network authentication and remote interactive logon can be distinct stages.

Say:

> “This suggests password guessing followed by valid-account access, but the logs cannot prove how the password was obtained. I would validate the session with the user and check the access path.”

## 2:30–3:45 — Pivot and decode without executing

```powershell
python -m soclab show 'WS-FIN-01|Microsoft-Windows-Sysmon/Operational|2001' --decode
python -m soclab show 'WS-FIN-01|Microsoft-Windows-Sysmon/Operational|2002'
```

Show `LogonId=0x9f2a`, then the matching ProcessGuid. The decoded command is an HTTP request to a fictional `.invalid` hostname. Explain that the command is displayed only, and that the TCP/443 record does not show response content or exfiltration.

Say:

> “I use the logon ID with host context to link the process to the session, then ProcessGuid to link network activity. A PID alone may be reused.”

## 3:45–4:45 — Establish the privilege and persistence evidence

```powershell
python -m soclab show 'WS-FIN-01|Security|1310'
python -m soclab show 'WS-FIN-01|Security|1312'
```

Use the report timeline to show 4720 record 1311 immediately before 4732 record 1312. The new account SID ending in `-1501` matches MemberSid; `S-1-5-32-544` identifies Administrators. The task action references `C:\Users\Public\Libraries\update.ps1` with a logon trigger. Record 1313 later records log clearing under the same subject logon ID.

Say:

> “I can show registration and group membership, but I cannot show that the task ran or the new account was used. The existing privileged session does not prove a privilege-escalation exploit.”

## 4:45–5:45 — Demonstrate judgment on a benign alert

```powershell
python -m soclab show 'WS-FIN-01|Microsoft-Windows-Sysmon/Operational|2000' --decode
```

Open CHG-1042 in `docs/case-brief.md`. Compare the decoded output message, `svc_inventory`, approved time, and InventoryAgent parent.

Say:

> “This matches my broad PowerShell rule, but the supplied change record explains it. I close it as expected activity in this exercise. In a real case I would validate that authorization and the parent process before applying a narrow exception.”

## 5:45–7:00 — Present the incident handoff

Open `docs/incident-report.md` at the executive assessment and response table. Explain High severity: privileged remote session, suspected persistence, a new administrator, and audit clearing. Propose user/change validation, approved endpoint isolation, account/session containment, and evidence preservation. Distinguish the proposed response from actions already performed—none were.

Say:

> “I would escalate this as a suspected account compromise. I have strong evidence of the sequence, but incomplete evidence of intent and impact. The next collection priorities are the script and task history, EDR process context, and identity, DNS, and proxy logs.”

## 7:00–8:00 — Explain a test and a limitation

Open `tests/test_lab.py` at `test_auth_window_inclusive` or `test_admin_join_uses_sid_and_host`. Explain why a 300-second boundary matches, a 301-second record can drop the failure count below threshold, and cross-host records must not correlate.

Say:

> “These rules are a custom Python lab format, not deployed SIEM content. The sequence engine scans a small batch and does not scale to an enterprise stream. I would translate the logic into the target platform, validate field mapping and event coverage, and measure alert quality on representative data.”

## Optional live threshold experiment

This changes the threshold only in memory and leaves the evidence and source rules untouched:

```powershell
python -c "from soclab.core import *; e=parse_events(ROOT/'data/windows-events.xml'); r=load_rules(); r[0]['min_prior']=7; a=detect(e,r); print(len(a), 'alerts'); print([x['rule_id'] for x in a])"
```

Expected: `5 alerts`, followed by `['R002', 'R002', 'R003', 'R004', 'R005']`. There are six failures, so requiring seven removes R001. Raising a threshold can reduce volume while missing a suspicious sequence; it is not automatically better tuning.

## Likely follow-up questions

| Question | Answer to demonstrate understanding |
|---|---|
| Is encoded PowerShell malicious? | No. Investigate decoded content, process ancestry, user/session, network behavior, and authorization. |
| Why local group SID instead of group name? | SID matching avoids localized or altered group names; MemberSid links the account even when MemberName is absent. |
| Why are logs available after clearing? | The fictional scenario models earlier forwarding. A local post-clear export alone would not supply the same history. |
| Did you detect command and control? | I found a process/network association. I cannot establish C2 from this fixture alone. |
| What did you miss? | Slow/distributed guessing, password spraying, other PowerShell parameter spellings, other persistence paths, existing-account admin additions, and non-1102 tampering. |
| What would you improve next? | Add real exported fixtures from an authorized VM, a failures-only rule, SIEM field mapping, and a measured benign baseline; preserve the existing regression cases. |
| How do you measure success? | Reproducible evidence joins and defensible triage here. Synthetic exact matches do not provide a real-world precision/recall estimate. |

If you only have two minutes, show the six-alert summary, explain one SID/session join, show why inventory PowerShell is benign, and give the incident conclusion plus one evidence gap.
