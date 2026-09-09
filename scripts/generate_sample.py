"""Rebuild deterministic, reduced synthetic Windows XML; no actions are executed."""
from pathlib import Path
import base64
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from soclab.core import NS

SEC = "Security"
SYS = "Microsoft-Windows-Sysmon/Operational"
AUDIT = "Microsoft-Windows-Security-Auditing"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
SID = "S-1-5-21-111111111-222222222-333333333"
DOMAIN_SID = "S-1-5-21-444444444-555555555-666666666"
GUID = "{b04d8640-0a15-6500-0000-001000000001}"
ET.register_namespace("", NS["e"])


def build():
    events = []
    def add(at, record, event_id, data, host="WS-FIN-01", channel=SEC):
        provider = "Microsoft-Windows-Sysmon" if channel == SYS else "Microsoft-Windows-Eventlog" if event_id == 1102 else AUDIT
        events.append(dict(at=at, record=record, event_id=event_id, data={k: str(v) for k, v in data.items()}, host=host, channel=channel, provider=provider))
    def auth(user, ip, success=True, logon_type=3, domain="NORTHSTAR", logon="0x1010"):
        rid = {"a.patel": "1101", "m.chen": "1102", "j.morgan": "1105"}[user]
        data = dict(TargetUserName=user, TargetDomainName=domain, TargetUserSid=DOMAIN_SID + "-" + rid if success else "S-1-0-0",
                    IpAddress=ip, IpPort=51432, LogonType=logon_type, AuthenticationPackageName="Negotiate",
                    WorkstationName="-", SubjectUserSid="S-1-5-18", SubjectUserName="WS-FIN-01$",
                    SubjectDomainName="NORTHSTAR", SubjectLogonId="0x3e7")
        if success:
            data.update(TargetLogonId=logon, LogonProcessName="User32" if logon_type == 10 else "NtLmSsp")
        else:
            data.update(Status="0xc000006d", SubStatus="0xc000006a", FailureReason="%%2313", LogonProcessName="NtLmSsp")
        return data
    start = datetime(2026, 8, 18, 8, tzinfo=timezone.utc)
    for i in range(120):
        time = (start + timedelta(seconds=i * 30)).isoformat().replace("+00:00", "Z")
        host = "WS-FIN-01" if i % 2 == 0 else "WS-HR-02"
        data = auth("a.patel" if i % 2 == 0 else "m.chen", "10.20.5.10", logon=str(hex(4096 + i)))
        data["SubjectUserName"] = host + "$"
        add(time, 1000 + i, 4624, data, host=host)
    # Two ordinary typing mistakes, below the correlation threshold.
    for i in range(2):
        add(f"2026-08-18T09:00:0{i}Z", 1200 + i, 4625, auth("a.patel", "10.20.5.10", False))
    add("2026-08-18T09:00:15Z", 1202, 4624, auth("a.patel", "10.20.5.10"))
    # A benign encoded job intentionally remains an alert to teach triage.
    benign = base64.b64encode("Write-Output 'Northstar inventory check'".encode("utf-16-le")).decode()
    add("2026-08-18T09:05:00Z", 2000, 1, dict(Image=PS, CommandLine=f'powershell.exe -EncodedCommand {benign}',
        User="NORTHSTAR\\svc_inventory", LogonId="0x8800", ProcessGuid="{b04d8640-0905-6500-0000-001000000002}", ProcessId=3300,
        ParentImage=r"C:\Program Files\Northstar\InventoryAgent.exe", ParentCommandLine="InventoryAgent.exe --daily", ParentProcessId=1500,
        ParentProcessGuid="{b04d8640-0900-6500-0000-001000000003}", IntegrityLevel="High"), channel=SYS)
    task = '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers><Principals><Principal id="Author"><UserId>NORTHSTAR\\j.morgan</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><Enabled>true</Enabled></Settings><Actions Context="Author"><Exec><Command>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Command><Arguments>-NoProfile -File C:\\Users\\Public\\Libraries\\update.ps1</Arguments></Exec></Actions></Task>'
    add("2026-08-18T09:10:00Z", 1210, 4698, dict(SubjectUserName="svc_inventory", SubjectDomainName="NORTHSTAR", SubjectLogonId="0x8800", TaskName="\\Northstar\\Inventory", TaskContent=task.replace("NORTHSTAR\\j.morgan", "NORTHSTAR\\svc_inventory").replace(r"C:\Users\Public\Libraries\update.ps1", r"C:\Program Files\Northstar\inventory.ps1")))
    # Approved account provisioning that does not grant Administrators membership.
    add("2026-08-18T09:15:00Z", 1220, 4720, dict(TargetUserName="lab_reader", TargetDomainName="WS-FIN-01", TargetSid=SID + "-1500", SubjectUserName="it.admin", SubjectDomainName="NORTHSTAR", SubjectLogonId="0x9900"))
    add("2026-08-18T09:15:30Z", 1221, 4732, dict(TargetUserName="Users", TargetDomainName="Builtin", TargetSid="S-1-5-32-545", MemberSid=SID + "-1500", MemberName="-", SubjectUserName="it.admin", SubjectDomainName="NORTHSTAR", SubjectLogonId="0x9900"))
    for i in range(6):
        add(f"2026-08-18T10:14:{i * 10:02d}Z", 1300 + i, 4625, auth("j.morgan", "192.0.2.44", False))
    add("2026-08-18T10:15:20Z", 1306, 4624, auth("j.morgan", "192.0.2.44", logon_type=10, logon="0x9f2a"))
    add("2026-08-18T10:15:21Z", 1307, 4672, dict(SubjectUserSid=DOMAIN_SID + "-1105", SubjectUserName="j.morgan", SubjectDomainName="NORTHSTAR", SubjectLogonId="0x9f2a", PrivilegeList="SeDebugPrivilege SeBackupPrivilege SeRestorePrivilege"))
    encoded = base64.b64encode("Invoke-WebRequest -Uri 'https://telemetry.example.invalid/health' -UseBasicParsing".encode("utf-16-le")).decode()
    add("2026-08-18T10:16:00Z", 2001, 1, dict(Image=PS, CommandLine=f'powershell.exe -NoProfile -EncodedCommand {encoded}',
        User="NORTHSTAR\\j.morgan", LogonId="0x9f2a", ProcessGuid=GUID, ProcessId=4420,
        ParentImage=r"C:\Windows\explorer.exe", ParentCommandLine=r"C:\Windows\Explorer.EXE", ParentProcessId=4000,
        ParentProcessGuid="{b04d8640-1015-6500-0000-001000000004}", IntegrityLevel="High"), channel=SYS)
    add("2026-08-18T10:16:05Z", 2002, 3, dict(Image=PS, User="NORTHSTAR\\j.morgan", ProcessGuid=GUID, ProcessId=4420,
        Protocol="tcp", Initiated="true", SourceIp="10.20.10.21", SourcePort=50140, DestinationIp="198.51.100.25", DestinationPort=443,
        DestinationHostname="telemetry.example.invalid"), channel=SYS)
    add("2026-08-18T10:17:00Z", 1310, 4698, dict(SubjectUserName="j.morgan", SubjectDomainName="NORTHSTAR", SubjectLogonId="0x9f2a", TaskName="\\OneDrive Health Check", TaskContent=task))
    add("2026-08-18T10:18:00Z", 1311, 4720, dict(TargetUserName="svc_backup2", TargetDomainName="WS-FIN-01", TargetSid=SID + "-1501", SubjectUserName="j.morgan", SubjectDomainName="NORTHSTAR", SubjectLogonId="0x9f2a"))
    add("2026-08-18T10:18:30Z", 1312, 4732, dict(TargetUserName="Administrators", TargetDomainName="Builtin", TargetSid="S-1-5-32-544", MemberSid=SID + "-1501", MemberName="-", SubjectUserName="j.morgan", SubjectDomainName="NORTHSTAR", SubjectLogonId="0x9f2a"))
    add("2026-08-18T10:20:00Z", 1313, 1102, dict(SubjectUserSid=DOMAIN_SID + "-1105", SubjectUserName="j.morgan", SubjectDomainName="NORTHSTAR", SubjectLogonId="0x9f2a"))
    root = ET.Element("Events")
    for e in sorted(events, key=lambda x: (x['at'], x['record'])):
        def element(parent, name, text=None, **attrs):
            node = ET.SubElement(parent, f"{{{NS['e']}}}{name}", attrs)
            node.text = text
            return node
        node = element(root, "Event")
        system = element(node, "System")
        element(system, "Provider", Name=e["provider"])
        element(system, "EventID", str(e["event_id"]))
        element(system, "TimeCreated", SystemTime=e["at"])
        element(system, "EventRecordID", str(e["record"]))
        element(system, "Channel", e["channel"])
        element(system, "Computer", e["host"])
        if e["event_id"] == 1102:
            data = element(node, "UserData")
            log = ET.SubElement(data, "{http://manifests.microsoft.com/win/2004/08/windows/eventlog}LogFileCleared")
            for key, value in e["data"].items():
                ET.SubElement(log, "{http://manifests.microsoft.com/win/2004/08/windows/eventlog}" + key).text = value
        else:
            data = element(node, "EventData")
            for key, value in e["data"].items():
                element(data, "Data", value, Name=key)
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n", len(events)


if __name__ == "__main__":
    data, count = build()
    folder = ROOT / "data"
    folder.mkdir(exist_ok=True)
    (folder / "windows-events.xml").write_bytes(data)
    manifest = {"synthetic": True, "event_count": count, "sha256": {"data/windows-events.xml": hashlib.sha256(data).hexdigest()}}
    (folder / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Generated {count} synthetic events and manifest")
