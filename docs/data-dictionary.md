# Evidence format and collection assumptions

## Provenance

`scripts/generate_sample.py` authors all 141 records deterministically. It does not read the host's event logs. `data/manifest.json` stores the SHA-256 digest of the XML. `python -m soclab verify` checks accidental changes against that digest. A manifest delivered beside evidence is not an independent authenticity guarantee or a forensic chain of custody. For real evidence, record collector, acquisition time, source, transfer history, and independently stored hashes.

The fixture covers 08:00:00–10:20:00 UTC on 2026-08-18. There are 127 baseline records and 14 records in the suspicious session sequence. Two hosts are represented. Baseline activity includes one intentionally alerting approved encoded PowerShell process. The tiny, selected record mix is educational and does not model normal enterprise event rates.

## Fields and joins

| Field | Meaning / use in this lab |
|---|---|
| `System/TimeCreated/@SystemTime` | Event time normalized to UTC; timezone is required |
| `System/Provider/@Name`, `Channel`, `EventID` | Combined event source identity; an ID alone is insufficient |
| `Computer` + `Channel` + `EventRecordID` | Export reference, joined with `|`; duplicate references are rejected |
| `TargetUserName`, `TargetDomainName`, `IpAddress` | Authentication correlation key alongside host |
| `TargetLogonId` (4624) | New session identifier; join to subject/process logon IDs on the same host |
| `SubjectUserName`, `SubjectLogonId` | Identity/session performing an action, distinct from its target |
| `ProcessGuid` (Sysmon 1 / 3) | Joins process creation and network connection on a host; preferable to a reusable PID |
| `TargetSid` (4720) → `MemberSid` (4732) | Links a created account to the group member; names can be missing |
| `TargetSid` (4732) | Group receiving the member; `S-1-5-32-544` is local Administrators |
| `TaskContent` (4698) | Escaped task XML inside an EventData string; no task is registered by parsing it |
| `UserData/LogFileCleared/*` (1102) | Separate namespace containing the subject of Security log clearing |

Logon IDs are local to the host and may be reused across reboot boundaries; the short lab window contains no reboot. The engine compares join strings case-insensitively but does not canonicalize alternate SID, hexadecimal, DNS/NetBIOS, or IP representations. Missing, empty, and `-` join values cannot match. A real collector requires stronger normalization, boot context, retention, and clock-skew handling.

## Event semantics and real collection prerequisites

| Events | Meaning | Prerequisite in an authorized Windows lab |
|---|---|---|
| 4624 / 4625 | Successful / failed logon at the destination | Relevant Audit Logon success/failure policy; RDP with NLA can involve type 3 failures before type 10 success |
| 4672 | Special privileges assigned to a new logon | Audit Special Logon; this supports privilege context, not proof of an exploit |
| 4698 | Scheduled task created | Audit Other Object Access Events success; task content must be retained |
| 4720 | User account created | Audit User Account Management success |
| 4732 | Member added to a security-enabled local group | Audit Security Group Management success |
| 1102 | Security audit log cleared | Collect Security channel and preserve forwarded copies; the event uses Microsoft-Windows-Eventlog |
| Sysmon 1 / 3 | Process creation / network connection | Sysmon installed and configured; network connection logging must be enabled and may be filtered |

These are deployment prerequisites, not configuration performed by this repository. The offline exercise works without them. Verify effective policy, Sysmon configuration, forwarding, permissions, and schema on a separate authorized VM before adapting the rules to real events. No EVTX reader or live collector is included.

Microsoft defines logon types 3 (network) and 10 (remote interactive), and records the new session ID in 4624. The fixture's RDP interpretation uses the type 10 success; the preceding type 3 failures alone do not establish RDP. See [4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) and [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625).

Microsoft documents task creation and account/group audit semantics in [4698](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698), [4720](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720), and [4732](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732). [1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102) describes Security log clearing. [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) documents process and network telemetry and its configuration.

## Parser boundaries

Accepted input: UTF-8 Windows event XML, either one namespaced `Event` or an `Events` wrapper containing namespaced events. DTD/entity declarations, duplicate event identities, missing System fields, invalid timestamps, and malformed XML fail the run. Unsupported/missing event-specific fields remain absent and will not match required rule fields. Unknown event IDs remain in the timeline. An empty CLI input fails with an explanatory error and exit code 2.

This is a small batch parser, not a hostile-input ingestion service: no streaming, size quotas, field-level schema validation for every Windows event, or deduplication across separate runs. Record IDs can reset after log clearing; merged exports spanning resets may need an additional source-generation identifier. Data is never passed to a shell. `show --decode` only Base64-decodes UTF-16LE text. CSV cells that could begin spreadsheet formulas are prefixed with an apostrophe; normalized JSON retains the original data.
