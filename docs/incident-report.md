# Incident report — NS-2026-0818

**Training case · Recommended disposition: escalate · Severity: High**

Window: August 18, 2026, 08:00–10:20 UTC. This report uses synthetic evidence and the change records supplied with the lab.

## Summary

WS-FIN-01 shows a suspicious remote interactive session using `NORTHSTAR\j.morgan` after six failed authentications from the same source. The session is linked to encoded PowerShell, an outbound connection, scheduled-task registration, creation of a local account followed by Administrators membership, and Security log clearing. No matching change authorization is supplied. Escalate as a suspected account compromise affecting one finance workstation.

Severity is High because the session has privileged access, registers a persistence mechanism, adds an administrator, and clears the audit log. The event sequence is clear; malicious intent still needs user and change-owner validation. Password guessing is plausible, not confirmed. Neither data theft, lateral movement, a downloaded payload, nor successful scheduled-task execution is established.

## Scope and evidence

The dataset contains 141 synthetic events across two endpoints. Fourteen records belong to the suspicious sequence; five alerts cover part of that sequence. A sixth alert is an approved inventory job. WS-HR-02 appears only in supplied baseline activity; lack of suspicious evidence there does not establish that the wider environment is clean.

All references below use host **WS-FIN-01**. `Security/1306` expands to `WS-FIN-01|Security|1306`; `Sysmon/2001` expands to `WS-FIN-01|Microsoft-Windows-Sysmon/Operational|2001`. See `data/manifest.json` for the source digest and `sample-output/` for reproducible evidence exports. The hash verifies consistency with the supplied fixture, not independent authenticity.

## Timeline

| UTC, 2026-08-18 | Evidence | Observation | Interpretation / limit |
|---|---|---|---|
| 09:05:00 | Sysmon 1, record 2000 | `svc_inventory`, inventory-agent parent, encoded output message | Matches fictional CHG-1042; expected automation |
| 10:14:00–10:14:50 | Security 4625, 1300–1305 | Six type 3 failures for `NORTHSTAR\j.morgan` from `192.0.2.44`; SubStatus `0xc000006a` | Wrong-password failures consistent with guessing; not proof of attacker identity |
| 10:15:20 | Security 4624, 1306 | Type 10 success, same user/source, `TargetLogonId=0x9f2a` | Remote interactive logon observed, 80 seconds after first failure |
| 10:15:21 | Security 4672, 1307 | Special privileges assigned to `j.morgan`, session `0x9f2a` | Privileged context; no elevation exploit shown |
| 10:16:00 | Sysmon 1, 2001 | PowerShell with EncodedCommand, `LogonId=0x9f2a`, high integrity | Suspicious in context; inspect decoded content |
| 10:16:05 | Sysmon 3, 2002 | Same ProcessGuid connects to `198.51.100.25:443` | Supports process/network association; response and bytes unknown |
| 10:17:00 | Security 4698, 1310 | `\OneDrive Health Check` task; logon trigger; PowerShell `-File C:\Users\Public\Libraries\update.ps1` | Possible persistence via task; filename is not proof of vendor origin; execution unproven |
| 10:18:00 | Security 4720, 1311 | Local `WS-FIN-01\svc_backup2` created by `j.morgan` in session `0x9f2a` | Unapproved account creation in supplied context |
| 10:18:30 | Security 4732, 1312 | Created SID ending `-1501` added to group SID `S-1-5-32-544` | Local Administrators membership observed |
| 10:20:00 | Security 1102, 1313 | `j.morgan`, `SubjectLogonId=0x9f2a`, cleared Security audit log | Suspected evasion; could be maintenance, but no approval is supplied |

## Correlation reasoning

R001 joins host, domain, account, and source IP; all six failures occur within 300 seconds before the success. Type 3 failures alone are network authentication events. Type 10 in the later success supplies the remote interactive evidence. A failed-password burst followed by success is also possible for a legitimate user, so authentication alone would require validation.

The successful logon's `TargetLogonId=0x9f2a` matches the PowerShell `LogonId` and the Security actions' `SubjectLogonId` on WS-FIN-01. The PowerShell process and the connection share `ProcessGuid={b04d8640-0a15-6500-0000-001000000001}`. Account creation `TargetSid=S-1-5-21-111111111-222222222-333333333-1501` equals group-addition `MemberSid`; the destination group SID establishes Administrators even though `MemberName` is `-`.

These are explicit field joins. Timing alone would be weaker. They link the supplied activity to an account/session, not to the human operating it. R001 and R004 perform automated correlations; the wider chain across the five alerts is an analyst assessment, not an automatic incident correlation feature.

Decoded PowerShell in record 2001, displayed as text only:

```powershell
Invoke-WebRequest -Uri 'https://telemetry.example.invalid/health' -UseBasicParsing
```

This expresses a web request and is consistent with the illustrative network event. The logs do not include an HTTP status, response body, file write, or exfiltration evidence. The destination is a reserved fictional label. No web request was made by the lab.

## Alert dispositions

| Rule / evidence | Disposition | Reason |
|---|---|---|
| R001 / 1300–1306 | Escalate: suspicious | Burst plus remote success, reinforced by later actions |
| R002 / 2000 | Close: expected activity in exercise | Time, service user, inventory-agent parent, and decoded output message match CHG-1042 |
| R002 / 2001 | Escalate: suspicious in context | Linked privileged session and network behavior; no approved task |
| R003 / 1310 | Escalate: suspected persistence | Logon-triggered script under Public; no supplied authorization |
| R004 / 1311–1312 | Escalate: unexpected privilege change | New local account immediately receives Administrators membership |
| R005 / 1313 | Escalate: suspected evasion | Same session clears Security log after changes |

The approved encoded command is a correct match to broad encoded-command logic, but a benign result for incident triage. Do not call it a detector malfunction. In a real investigation, verify the change owner, agent provenance, command, and host before closure. Do not globally allowlist encoded PowerShell.

## Proposed response and handoff

These are proposed actions for the incident lead and response team. No containment was performed in this lab.

| Priority | Proposed action / owner | Purpose and constraint |
|---|---|---|
| Immediate | Incident lead validates with the user and change owner through a trusted channel | Resolve authorization independently of the possibly compromised session |
| Immediate | Endpoint responder isolates WS-FIN-01 using approved EDR controls | Limit further access while preserving the investigation channel; assess finance impact |
| Immediate | Identity responder disables/restricts affected accounts as appropriate, revokes active sessions, and resets affected credentials from a trusted system | Contain use of `j.morgan` and the unexpected local account; include service dependencies in decisions |
| Immediate | Forensic responder preserves forwarded logs, task XML, account/group state, and available volatile evidence | Avoid rebooting or deleting artifacts before collection where feasible; document acquisition and hashes |
| Next | Detection/IR team hunts source, destination, account SID, task path/name, and related sessions across EDR, DC, VPN/RDP, DNS and proxy logs | Establish reach, access mechanism, response content, and any transfer; do not treat these fictional IOCs as real block targets |
| After preservation | Endpoint responder removes unauthorized task/account and repairs or rebuilds according to findings | Verify eradication; do not assume deleting a task alone resolves compromise |
| Recovery | System owner and incident lead verify clean state, restore service, monitor recurrence, and review local-admin exception | Close only with documented scope, containment, artifact resolution, user validation, and monitoring results |

## Open questions and limits

1. Was the session authorized? The supplied register lacks an approval, but the account owner has not been contacted.
2. How were credentials obtained? Authentication events cannot distinguish guessing, prior theft, or an authorized user's mistakes with certainty.
3. What did `update.ps1` contain, and did the task run? Neither file contents nor task execution telemetry are supplied.
4. Did the web request succeed or transfer sensitive data? Network connection telemetry alone cannot answer this.
5. Were other hosts or accounts affected? The selected two-host fixture cannot support enterprise-wide conclusions.
6. Was evidence lost before forwarding? The exercise assumes selected records were retained; collection delays and gaps are not modeled.

Relevant technique mappings, tuning considerations, and primary ATT&CK references are in the [detection reference](../rules/README.md). Event meanings and Microsoft sources are in the [data dictionary](data-dictionary.md).
