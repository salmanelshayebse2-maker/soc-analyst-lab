# Analyst investigation worksheet

Try this before opening the incident report. Budget 30–45 minutes on the first pass. Your outputs are a scoped timeline, alert dispositions, a short escalation, and a list of evidence still needed.

## 1. Establish integrity and scope

Run `python -m soclab verify`, then `python -m soclab run`. Record event count, date range, channels, affected hosts, and the hash from the manifest. Explain what the hash proves and what it cannot prove. Review the collection assumptions and change records in the case brief.

Questions: Is the XML a native EVTX file? Are earlier records available because log clearing failed, or because the exercise models forwarding? Can one host/channel record number identify an event globally?

## 2. Start with authentication

Inspect `WS-FIN-01|Security|1300` and `WS-FIN-01|Security|1306` with `python -m soclab show '<reference>'`. Compare username, domain, source address, logon types, timestamps, and failure status/substatus. Use `results/timeline.csv` to count the matching failures and calculate the elapsed time.

Questions: Which field identifies the new session? Why do type 3 failures and type 10 success not contradict each other? Could a legitimate user generate this sequence? What corroboration would you seek?

## 3. Pivot into process and network telemetry

Inspect Sysmon records 2001 and 2002 on WS-FIN-01. Decode 2001 using `show --decode`. Link process creation to the authentication session by host, user, and logon ID; then link process creation to the network event by host and ProcessGuid.

Questions: Why prefer ProcessGuid over PID alone? Does a TCP connection on port 443 establish an HTTP response, malicious command and control, or exfiltration? Is the decoded command enough to recover a script or payload?

## 4. Examine persistence and account changes

Inspect Security 1310–1312. Read TaskContent rather than judging the task name. Find the action, logon trigger, account context, and script path. Match the created account SID to MemberSid and identify the group using its SID.

Questions: Did the evidence show task registration or task execution? Does 4672 prove an elevation exploit? Why is `MemberName=-` not a dead end? Is the new account local or domain-based?

## 5. Triage the benign alert

Decode Sysmon record 2000. Compare it with CHG-1042: time, account, parent, and decoded content. Document a disposition for that alert while explaining which checks you would independently validate in a real case. Review the ordinary task and Users-group addition to understand why they do not match R003/R004.

## 6. Write your handoff

Use this template:

```text
Case / severity / confidence:
Affected assets and identities:
Observed facts with evidence references:
Hypotheses and alternative explanations:
Alert dispositions:
Immediate proposed actions and owners:
Missing evidence / next pivots:
Criteria for recovery and closure:
```

Include at least one observation you are highly confident in and one conclusion you cannot support. Mark proposed response actions as proposed. Compare your handoff to the incident report only after completing it.
