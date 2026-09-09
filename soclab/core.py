"""Parse reduced Windows XML exports and run the documented lab rule format."""
from __future__ import annotations

import base64
import csv
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
ROOT = Path(__file__).resolve().parents[1]


def timestamp(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")
    return dt.astimezone(timezone.utc)


def reference(event):
    return "|".join(str(event[k]) for k in ("Computer", "Channel", "EventRecordID"))


def parse_events(path):
    raw = Path(path).read_bytes()
    # This parser accepts UTF-8 XML only, not binary EVTX or UTF-16 exports.
    xml = raw.decode("utf-8-sig")
    if re.search(r"<!\s*(DOCTYPE|ENTITY)\b", xml, re.I):
        raise ValueError("DTD/entity declarations are not supported")
    root = ET.fromstring(xml)
    nodes = [root] if root.tag == f"{{{NS['e']}}}Event" else list(root)
    if root.tag not in ("Events", f"{{{NS['e']}}}Events", f"{{{NS['e']}}}Event"):
        raise ValueError("Expected Events wrapper or namespaced Event")
    events, seen = [], set()
    for node in nodes:
        if node.tag != f"{{{NS['e']}}}Event":
            raise ValueError("Unexpected element in Events")
        system = node.find("e:System", NS)
        if system is None:
            raise ValueError("Event missing System")
        def required(name):
            value = system.findtext(f"e:{name}", namespaces=NS)
            if not value:
                raise ValueError(f"Missing System/{name}")
            return value
        provider = system.find("e:Provider", NS)
        time = system.find("e:TimeCreated", NS)
        if provider is None or not provider.get("Name") or time is None:
            raise ValueError("Missing provider or timestamp")
        event = {"EventID": int(required("EventID")),
                 "EventRecordID": int(required("EventRecordID")),
                 "Computer": required("Computer"), "Channel": required("Channel"),
                 "Provider": provider.get("Name"),
                 "TimeCreated": timestamp(time.attrib["SystemTime"]).isoformat().replace("+00:00", "Z")}
        data = {}
        for item in node.findall("e:EventData/e:Data", NS):
            name = item.get("Name")
            if not name or name in data:
                raise ValueError("Unnamed or duplicate EventData field")
            data[name] = item.text or ""
        # Event 1102 uses UserData/LogFileCleared in its own namespace.
        for item in node.findall("e:UserData", NS):
            for leaf in item.iter():
                if len(leaf) == 0:
                    name = leaf.tag.rsplit("}", 1)[-1]
                    if name in data:
                        raise ValueError("Duplicate UserData field")
                    data[name] = leaf.text or ""
        event["EventData"] = data
        ref = reference(event)
        if ref in seen:
            raise ValueError(f"Duplicate event identity: {ref}")
        seen.add(ref)
        events.append(event)
    return sorted(events, key=lambda e: (timestamp(e["TimeCreated"]), reference(e)))


def field(event, key):
    return event.get(key, event["EventData"].get(key))


def matches(event, selection):
    for expression, expected in selection.items():
        key, _, op = expression.partition("|")
        actual = field(event, key)
        if actual is None or str(actual).strip() in ("", "-"):
            return False
        value = str(actual).casefold()
        values = expected if isinstance(expected, list) else [expected]
        if op == "regex":
            ok = any(re.search(str(v), str(actual), re.I) for v in values)
        elif op == "contains":
            ok = any(str(v).casefold() in value for v in values)
        elif op == "endswith":
            ok = any(value.endswith(str(v).casefold()) for v in values)
        elif not op:
            ok = any(value == str(v).casefold() for v in values)
        else:
            raise ValueError(f"Unsupported operator: {op}")
        if not ok:
            return False
    return True


def load_rules(path=ROOT / "rules"):
    rules = [json.loads(p.read_text(encoding="utf-8-sig")) for p in sorted(Path(path).glob("*.json"))]
    if not rules or len({r["id"] for r in rules}) != len(rules):
        raise ValueError("Rules must be nonempty with unique IDs")
    for rule in rules:
        if rule["kind"] not in ("single", "sequence"):
            raise ValueError("Unknown rule kind")
        if rule["kind"] == "sequence" and (rule["window_seconds"] <= 0 or rule["min_prior"] < 1):
            raise ValueError("Invalid sequence threshold")
        for selection in [rule["selection"]] if rule["kind"] == "single" else [rule["prior"], rule["current"]]:
            for expression, value in selection.items():
                op = expression.partition("|")[2]
                if op not in ("", "contains", "endswith", "regex"):
                    raise ValueError(f"Unsupported operator: {op}")
                if op == "regex":
                    for pattern in value if isinstance(value, list) else [value]:
                        re.compile(pattern, re.I)
    return rules


def same_join(prior, current, mapping):
    for left, right in mapping.items():
        a, b = field(prior, left), field(current, right)
        if a is None or b is None or str(a).strip() in ("", "-") or str(b).strip() in ("", "-"):
            return False
        if str(a).casefold() != str(b).casefold():
            return False
    return True


def detect(events, rules):
    events = sorted(events, key=lambda e: (timestamp(e["TimeCreated"]), reference(e)))
    alerts = []
    for rule in rules:
        for current in events:
            if rule["kind"] == "single":
                if not matches(current, rule["selection"]):
                    continue
                evidence = [current]
            else:
                if not matches(current, rule["current"]):
                    continue
                evidence = [prior for prior in events
                            if matches(prior, rule["prior"])
                            and 0 < (timestamp(current["TimeCreated"]) - timestamp(prior["TimeCreated"])).total_seconds() <= rule["window_seconds"]
                            and same_join(prior, current, rule["join"])]
                if len(evidence) < rule["min_prior"]:
                    continue
                evidence += [current]
            refs = [reference(e) for e in evidence]
            alerts.append({"alert_id": hashlib.sha256((rule["id"] + "\n" + "\n".join(refs)).encode()).hexdigest()[:12],
                           "rule_id": rule["id"], "title": rule["title"], "severity": rule["severity"],
                           "attack": rule["attack"], "time": current["TimeCreated"],
                           "computer": current["Computer"], "evidence": refs,
                           "disposition": "needs_review"})
    return sorted(alerts, key=lambda a: (a["time"], a["rule_id"], a["alert_id"]))


def decode_command(command):
    match = re.search(r'(?:^|\s)-(?:enc|encodedcommand)\s+[\"\']?([A-Za-z0-9+/=]+)', command, re.I)
    if not match:
        raise ValueError("No supported -enc or -EncodedCommand token")
    return base64.b64decode(match.group(1), validate=True).decode("utf-16-le")


def verify_manifest(root=ROOT):
    manifest = json.loads((root / "data/manifest.json").read_text(encoding="utf-8"))
    for name, expected in manifest["sha256"].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root.resolve()):
            raise ValueError("Manifest path outside project")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"SHA-256 mismatch: {name}")
    return manifest


def write_results(events, alerts, out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "alerts.json").write_text(json.dumps(alerts, indent=2) + "\n", encoding="utf-8")
    (out / "normalized.jsonl").write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in events), encoding="utf-8")
    with (out / "timeline.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["utc", "reference", "event_id", "user", "details_json"])
        for event in events:
            data = event["EventData"]
            # Prefix spreadsheet formula-leading cells; evidence remains intact in JSONL.
            cells = [event["TimeCreated"], reference(event), event["EventID"],
                     data.get("User", data.get("TargetUserName", data.get("SubjectUserName", ""))),
                     json.dumps(data, sort_keys=True)]
            writer.writerow(["'" + c if isinstance(c, str) and c.lstrip().startswith(("=", "+", "-", "@")) else c for c in cells])
    counts = Counter(a["rule_id"] for a in alerts)
    summary = ["# Detection run", "", "Synthetic training evidence; alerts require analyst review.", "",
               f"Events: {len(events)} | Alerts: {len(alerts)}", "", "| Rule | Alerts |", "|---|---:|"]
    summary += [f"| {key} | {value} |" for key, value in sorted(counts.items())]
    summary += ["", "See alerts.json for full evidence references and timeline.csv for all events.", ""]
    (out / "summary.md").write_text("\n".join(summary), encoding="utf-8")
