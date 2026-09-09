# Case brief — NS-2026-0818

**All evidence and business context are fictional.** Your role is a junior SOC analyst preparing an escalation for a senior analyst. Exercise date: August 18, 2026. All timeline times are UTC.

## Environment

| Asset / identity | Fictional context |
|---|---|
| WS-FIN-01 / 10.20.10.21 | Finance workstation; Windows member endpoint |
| WS-HR-02 | Second workstation providing ordinary logon background |
| NORTHSTAR | Fictional Windows domain |
| NORTHSTAR\j.morgan | Finance application support user; existing local administrator exception on WS-FIN-01 |
| NORTHSTAR\svc_inventory | Approved inventory service identity |
| NORTHSTAR\it.admin | IT account used for approved provisioning |
| 10.20.5.10 | Internal management address |
| 192.0.2.44 | External source label in this synthetic exercise; not an attributable real attacker |
| 198.51.100.25 / telemetry.example.invalid | Synthetic network destination, not a live IOC |

The fixture represents a merged, previously forwarded collection of Security and Sysmon events. Collection time is not modeled; event timestamps are treated as synchronized UTC. Earlier events survived in this hypothetical collector even though the endpoint later recorded Security log clearing. Record IDs identify source host/channel records; they are not global identifiers. Gaps are intentional because this is a selected dataset.

## Fictional change records available to the analyst

| Change | Window (UTC) | Approved activity |
|---|---|---|
| CHG-1042 | 09:00–09:10 | InventoryAgent.exe launches encoded PowerShell as `svc_inventory`; decoded text is `Write-Output 'Northstar inventory check'`. Expected parent: `C:\Program Files\Northstar\InventoryAgent.exe`. |
| CHG-1043 | 09:10–09:20 | `svc_inventory` registers `\Northstar\Inventory` using the script under `C:\Program Files\Northstar\`. |
| CHG-1044 | 09:10–09:20 | `it.admin` creates local `lab_reader` and adds it to the local **Users** group, not Administrators. |

The exercise change register contains no approved `j.morgan` activity between 10:14 and 10:20, no `svc_backup2` creation, no `\OneDrive Health Check` registration, and no Security log clearing. This absence raises concern; it is not independent proof of malicious intent. Contacting the user or change owner is a proposed next step, not an action already performed.

## Your assignment

Identify the affected endpoint, account, source address, session, and event sequence. Explain why one PowerShell alert should be closed as expected activity. Assess severity, document at least three evidence gaps, and propose a prioritized containment and investigation handoff.

There is no supplied file content for `update.ps1`, no task execution event, no packet capture, no directory-controller or VPN logs, and no EDR verdict. Do not invent findings for those sources. The encoded HTTP request and network event were authored as illustrative evidence; no DNS resolution, connection, or script execution occurred when this dataset was generated.
