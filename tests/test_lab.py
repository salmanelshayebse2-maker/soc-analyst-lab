import copy
import csv
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from soclab.core import ROOT, decode_command, detect, load_rules, parse_events, reference, timestamp, verify_manifest, write_results
from scripts.generate_sample import build


class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = parse_events(ROOT / 'data/windows-events.xml')
        cls.rules = load_rules()

    def event(self, record):
        return copy.deepcopy(next(e for e in self.events if e['EventRecordID'] == record))

    def rule(self, rule_id):
        return [r for r in self.rules if r['id'] == rule_id]

    def auth_sequence(self):
        return [self.event(n) for n in range(1300, 1307)]

    def test_manifest_and_count(self):
        self.assertEqual(verify_manifest()['event_count'], len(self.events))
        self.assertEqual(len(self.events), 141)

    def test_generator_is_reproducible(self):
        data, count = build()
        self.assertEqual(count, 141)
        self.assertEqual(data, (ROOT / 'data/windows-events.xml').read_bytes())

    def test_exact_expected_evidence(self):
        actual = [(a['rule_id'], [int(r.rsplit('|', 1)[1]) for r in a['evidence']]) for a in detect(self.events, self.rules)]
        self.assertEqual(actual, [('R002', [2000]), ('R001', list(range(1300, 1307))),
                                 ('R002', [2001]), ('R003', [1310]), ('R004', [1311, 1312]), ('R005', [1313])])

    def test_input_order_does_not_change_alerts(self):
        self.assertEqual(detect(self.events, self.rules), detect(list(reversed(self.events)), self.rules))

    def test_no_preassigned_verdicts(self):
        self.assertTrue(all(a['disposition'] == 'needs_review' for a in detect(self.events, self.rules)))

    def test_benign_alert_requires_triage(self):
        benign = [e for e in self.events if timestamp(e['TimeCreated']).hour < 10]
        alerts = detect(benign, self.rules)
        self.assertEqual([(a['rule_id'], a['evidence'][-1]) for a in alerts], [('R002', reference(self.event(2000)))])

    def test_auth_exact_threshold(self):
        seq = self.auth_sequence()[1:]
        self.assertEqual(len(detect(seq, self.rule('R001'))), 1)
        self.assertEqual(detect(seq[1:], self.rule('R001')), [])

    def test_auth_requires_success(self):
        self.assertEqual(detect(self.auth_sequence()[:-1], self.rule('R001')), [])

    def test_auth_window_inclusive(self):
        seq = self.auth_sequence()[1:]
        end = timestamp(seq[-1]['TimeCreated'])
        for e in seq[:-1]:
            e['TimeCreated'] = (end - timedelta(seconds=300)).isoformat()
        self.assertEqual(len(detect(seq, self.rule('R001'))), 1)
        seq[0]['TimeCreated'] = (end - timedelta(seconds=301)).isoformat()
        self.assertEqual(detect(seq, self.rule('R001')), [])

    def test_auth_rejects_same_or_later_timestamp(self):
        for offset in (0, 1):
            seq = self.auth_sequence()
            for e in seq[:-1]:
                e['TimeCreated'] = (timestamp(seq[-1]['TimeCreated']) + timedelta(seconds=offset)).isoformat()
            with self.subTest(offset=offset):
                self.assertEqual(detect(seq, self.rule('R001')), [])

    def test_auth_join_dimensions_and_missing(self):
        for key in ('Computer', 'TargetUserName', 'TargetDomainName', 'IpAddress'):
            for value in ('different', '', '-', None):
                seq = self.auth_sequence()
                obj = seq[-1] if key == 'Computer' else seq[-1]['EventData']
                obj[key] = value
                with self.subTest(key=key, value=value):
                    self.assertEqual(detect(seq, self.rule('R001')), [])

    def test_auth_case_insensitive_identity(self):
        seq = self.auth_sequence()
        seq[-1]['EventData']['TargetUserName'] = 'J.MORGAN'
        self.assertEqual(len(detect(seq, self.rule('R001'))), 1)

    def test_auth_local_logon_excluded(self):
        seq = self.auth_sequence()
        seq[-1]['EventData']['LogonType'] = '2'
        self.assertEqual(detect(seq, self.rule('R001')), [])

    def test_wrong_provider_or_channel_never_matches(self):
        for key in ('Provider', 'Channel'):
            events = copy.deepcopy(self.events)
            for e in events:
                e[key] = 'Wrong'
            with self.subTest(key=key):
                self.assertEqual(detect(events, self.rules), [])

    def test_encoded_detection_variants(self):
        for flag in ('-enc', '-EncodedCommand', '-ENC'):
            e = self.event(2001)
            e['EventData']['CommandLine'] = 'powershell.exe ' + flag + ' VwByAGkAdABlAA=='
            with self.subTest(flag=flag):
                self.assertEqual(len(detect([e], self.rule('R002'))), 1)

    def test_encoded_negative_controls(self):
        for command in ('powershell.exe -NoProfile Get-Date', 'powershell.exe -encoding utf8', 'powershell.exe -enc', ''):
            e = self.event(2001)
            e['EventData']['CommandLine'] = command
            with self.subTest(command=command):
                self.assertEqual(detect([e], self.rule('R002')), [])
        e['EventData']['CommandLine'] = self.event(2001)['EventData']['CommandLine']
        e['EventData']['Image'] = r'C:\Windows\notpowershell.exe'
        self.assertEqual(detect([e], self.rule('R002')), [])

    def test_decode_is_text_only(self):
        self.assertEqual(decode_command(self.event(2001)['EventData']['CommandLine']), "Invoke-WebRequest -Uri 'https://telemetry.example.invalid/health' -UseBasicParsing")
        with self.assertRaises(ValueError):
            decode_command('powershell.exe -enc abc')
        with self.assertRaises(ValueError):
            decode_command('powershell.exe Get-Date')

    def test_task_positive_and_negative(self):
        self.assertEqual(len(detect([self.event(1310)], self.rule('R003'))), 1)
        self.assertEqual(detect([self.event(1210)], self.rule('R003')), [])
        e = self.event(1310)
        del e['EventData']['TaskContent']
        self.assertEqual(detect([e], self.rule('R003')), [])

    def test_admin_join_uses_sid_and_host(self):
        for key, value in (('MemberSid', 'S-1-5-21-999'), ('MemberSid', ''), ('TargetSid', 'S-1-5-32-545')):
            pair = [self.event(1311), self.event(1312)]
            pair[1]['EventData'][key] = value
            with self.subTest(key=key, value=value):
                self.assertEqual(detect(pair, self.rule('R004')), [])
        pair[1] = self.event(1312)
        pair[1]['Computer'] = 'WS-HR-02'
        self.assertEqual(detect(pair, self.rule('R004')), [])

    def test_admin_ten_minute_boundary(self):
        pair = [self.event(1311), self.event(1312)]
        start = timestamp(pair[0]['TimeCreated'])
        for seconds, count in ((600, 1), (601, 0), (0, 0), (-1, 0)):
            pair[1]['TimeCreated'] = (start + timedelta(seconds=seconds)).isoformat()
            with self.subTest(seconds=seconds):
                self.assertEqual(len(detect(pair, self.rule('R004'))), count)

    def test_1102_userdata_parser(self):
        self.assertEqual(self.event(1313)['EventData']['SubjectLogonId'], '0x9f2a')
        self.assertEqual(len(detect([self.event(1313)], self.rule('R005'))), 1)

    def test_timezone_normalization(self):
        self.assertEqual(timestamp('2026-08-18T06:15:20-04:00'), timestamp('2026-08-18T10:15:20Z'))
        with self.assertRaises(ValueError):
            timestamp('2026-08-18T10:15:20')

    def parse_xml(self, text):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.xml'
            path.write_text(text, encoding='utf-8')
            return parse_events(path)

    def test_parser_rejects_duplicate_identity(self):
        import xml.etree.ElementTree as ET
        root = ET.parse(ROOT / 'data/windows-events.xml').getroot()
        root.append(copy.deepcopy(root[0]))
        with self.assertRaisesRegex(ValueError, 'Duplicate event identity'):
            self.parse_xml(ET.tostring(root, encoding='unicode'))

    def test_parser_rejects_bad_xml_and_missing_system(self):
        import xml.etree.ElementTree as ET
        for text in ('<Events>', '<Wrong/>', '<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"/></Events>', '<!DOCTYPE x [<!ENTITY y "bad">]><Events/>'):
            with self.subTest(text=text), self.assertRaises((ValueError, ET.ParseError)):
                self.parse_xml(text)

    def test_single_event_export(self):
        import xml.etree.ElementTree as ET
        first = ET.parse(ROOT / 'data/windows-events.xml').getroot()[0]
        self.assertEqual(len(self.parse_xml(ET.tostring(first, encoding='unicode'))), 1)

    def test_manifest_tamper_detection(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'data').mkdir()
            (root / 'data/manifest.json').write_bytes((ROOT / 'data/manifest.json').read_bytes())
            (root / 'data/windows-events.xml').write_text('changed')
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                verify_manifest(root)

    def test_outputs_reproducible_and_complete(self):
        alerts = detect(self.events, self.rules)
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            write_results(self.events, alerts, out)
            before = {p.name: p.read_bytes() for p in out.iterdir()}
            write_results(self.events, alerts, out)
            self.assertEqual(before, {p.name: p.read_bytes() for p in out.iterdir()})
            self.assertEqual(json.loads((out / 'alerts.json').read_text()), alerts)
            self.assertEqual(len((out / 'normalized.jsonl').read_text().splitlines()), 141)
            with (out / 'timeline.csv').open(newline='', encoding='utf-8') as handle:
                self.assertEqual(len(list(csv.reader(handle))), 142)

    def test_cli_full_run_and_errors(self):
        with tempfile.TemporaryDirectory() as folder:
            def cli(*args):
                return subprocess.run([sys.executable, '-m', 'soclab', *args], cwd=ROOT, capture_output=True, text=True)
            result = cli('run', '--out', folder)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('141 events; generated 6 alerts', result.stdout)
            self.assertEqual(cli('verify').returncode, 0)
            self.assertEqual(cli('show', 'WS-FIN-01|Microsoft-Windows-Sysmon/Operational|2001', '--decode').returncode, 0)
            for args in [('run', '--input', str(Path(folder) / 'missing.xml')), ('show', 'missing')]:
                result = cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertIn('ERROR:', result.stderr)
            path = Path(folder) / 'empty.xml'
            path.write_text('<Events/>')
            self.assertEqual(cli('run', '--input', str(path)).returncode, 2)
            rule_folder = Path(folder) / 'rules'
            rule_folder.mkdir()
            for rule in self.rules:
                (rule_folder / (rule['id'] + '.json')).write_text(json.dumps(rule), encoding='utf-8-sig')
            self.assertEqual(cli('run', '--rules', str(rule_folder), '--out', str(Path(folder) / 'bom-output')).returncode, 0)


if __name__ == '__main__':
    unittest.main()
