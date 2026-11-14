"""Offline regression tests: python3 -m unittest discover -s tests -v.

Only a temporary script copy bypasses root checks. Its command resolver is
replaced so it cannot reach real firewall/persistence binaries. curl and DNS
are fixture commands too; no privileges or network are needed.
"""

import gzip
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone


SOURCE = Path(__file__).resolve().parents[1] / 'block_ip'

MOCK = r'''#!/usr/bin/python3
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
root = Path(os.environ['FIXTURES'])
def option(key, default=''):
    return os.environ.get(key, default)
if name == 'curl':
    if '-o' in args:
        Path(args[args.index('-o') + 1]).write_text((root / 'feed.json').read_text())
        sys.exit(int(option('CURL_FAIL', '0')))
    print(option('GEO', '{}'))
    sys.exit(0)
if name in ('host', 'dig'):
    sys.exit(1)
if name == 'getent':
    if args[0] == 'hosts' and option('PTR'):
        print(args[1], option('PTR'))
        sys.exit(0)
    if args[0] == 'ahosts' and option('FORWARD'):
        print(option('FORWARD'), 'STREAM', args[1])
        sys.exit(0)
    sys.exit(1)
with (root / 'calls.jsonl').open('a') as f:
    f.write(json.dumps([name, *args]) + '\n')
if name == 'netfilter-persistent':
    sys.exit(int(option('SAVE_FAIL', '0')))
if option('READ_FAIL') and '-S' in args:
    sys.exit(4)
state_path = root / 'rules.json'
state = json.loads(state_path.read_text())
family = '6' if name == 'ip6tables' else '4'
rules = state[family]
op = next(x for x in ('-S', '-C', '-I', '-D') if x in args)
rule = args[args.index(op) + 2:]
if op == '-S':
    print('-P INPUT ACCEPT')
    for item in rules:
        print('-A INPUT ' + ' '.join(item))
    sys.exit(0)
if op == '-C':
    if option('CHECK_FAIL'):
        sys.exit(4)
    sys.exit(0 if rule in rules else 1)
if op == '-I':
    if option('INSERT_FAIL') == '1' or (option('INSERT_FAIL') and rule[1] == option('INSERT_FAIL')):
        sys.exit(4)
    rules.insert(0, rule)
if op == '-D':
    if option('DELETE_FAIL'):
        sys.exit(4)
    rules.remove(rule)
state_path.write_text(json.dumps(state))
'''


class BlockIPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='block-ip-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name in ('iptables', 'ip6tables', 'curl', 'getent', 'host', 'dig'):
            self.command(name)
        source = SOURCE.read_text()
        # Restrict privileged command discovery to fixtures, with no fallback.
        start = source.index('find_cmd() {')
        end = source.index('# Reverse DNS', start)
        source = source[:start] + '''find_cmd() {
  [ -x "$FIXTURES/bin/$1" ] || return 1
  printf '%s\\n' "$FIXTURES/bin/$1"
}

''' + source[end:]
        source = source.replace('${EUID:-$(id -u)}', '0')
        self.script = self.root / 'block_ip'
        self.script.write_text(source)
        self.feed = {'prefixes': [{'ipv4Prefix': '192.0.2.0/24'},
                                  {'ipv6Prefix': '2001:db8:1::/48'}]}
        (self.root / 'feed.json').write_text(json.dumps(self.feed))
        self.log = self.root / 'access.log'
        self.log.write_text('')
        self.allow = self.root / 'allow'
        self.allow.write_text('')
        self.set_rules()
        self.env = {**os.environ, 'PATH': f'{self.bin}:/usr/bin:/bin',
                    'FIXTURES': str(self.root), 'ALLOWLIST_FILE': str(self.allow),
                    'XDG_CACHE_HOME': str(self.root / 'cache'),
                    'ACCESS_LOG': str(self.log)}

    def command(self, name):
        path = self.bin / name
        path.write_text(MOCK)
        path.chmod(0o700)

    def set_rules(self, v4=None, v6=None):
        (self.root / 'rules.json').write_text(json.dumps({'4': v4 or [], '6': v6 or []}))

    def rules(self, family='4'):
        return json.loads((self.root / 'rules.json').read_text())[family]

    @staticmethod
    def rule(ip='203.0.113.10/32', web=False):
        return ['-s', ip] + (['-p', 'tcp', '-m', 'multiport', '--dports', '80,443'] if web else []) + ['-j', 'DROP']

    def line(self, ip='203.0.113.10', age=0):
        stamp = (datetime.now(timezone.utc) - timedelta(minutes=age)).strftime('%d/%b/%Y:%H:%M:%S %z')
        return f'{ip} - - [{stamp}] "GET / HTTP/1.1" 200 123 "-" "fixture"\n'

    def run_tool(self, *args, **env):
        return subprocess.run(['bash', str(self.script), *args], env={**self.env, **env},
                              capture_output=True, text=True, timeout=10)

    def auto(self, *args, **env):
        return self.run_tool('--autoblock', '10', '1', *args, **env)

    def calls(self):
        path = self.root / 'calls.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_web_only_autoblock_and_idempotence(self):
        self.log.write_text(self.line())
        p = self.auto()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.rules(), [self.rule(web=True)])
        self.assertIn('not saved them for reboot', p.stderr)
        p = self.auto()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('Blocked: 0, Already present: 1', p.stdout)
        self.assertEqual(len(self.rules()), 1)

    def test_manual_and_explicit_all_ports(self):
        self.log.write_text(self.line())
        for args in [('203.0.113.10',), ('--autoblock', '10', '1', '--all-ports')]:
            with self.subTest(args=args):
                self.set_rules()
                p = self.run_tool(*args)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(self.rules(), [self.rule()])

    def test_failed_insert_is_not_success(self):
        self.log.write_text(self.line())
        p = self.auto(INSERT_FAIL='1')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('Blocked: 0', p.stdout)
        self.assertIn('Failed: 1', p.stdout)
        self.assertNotIn('Blocked IP range:', p.stdout)
        self.assertEqual(self.rules(), [])
        p = self.run_tool('203.0.113.10', INSERT_FAIL='1')
        self.assertNotEqual(p.returncode, 0)

    def test_partial_success_is_saved_despite_failure(self):
        self.command('netfilter-persistent')
        self.log.write_text(self.line() + self.line('203.0.113.11'))
        p = self.auto(INSERT_FAIL='203.0.113.11/32')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('Blocked: 1', p.stdout)
        self.assertEqual(self.rules(), [self.rule(web=True)])
        self.assertIn(['netfilter-persistent', 'save'], self.calls())

    def test_save_failure_is_reported(self):
        self.command('netfilter-persistent')
        p = self.run_tool('203.0.113.10', SAVE_FAIL='1')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('live rules changed but saving them failed', p.stderr)
        self.assertEqual(self.rules(), [self.rule()])

    def test_firewall_read_or_check_error_cannot_insert(self):
        self.log.write_text(self.line())
        for env in ({'READ_FAIL': '1'}, {'CHECK_FAIL': '1'}):
            with self.subTest(env=env):
                p = self.auto(**env)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(self.rules(), [])
                self.assertFalse(any('-I' in c for c in self.calls()))

    def test_dry_run_performs_protections_without_firewall_calls(self):
        self.allow.write_text('203.0.113.11\n')
        self.log.write_text(''.join(self.line(ip) for ip in
                                   ['203.0.113.10', '203.0.113.11', '127.0.0.1',
                                    '192.0.2.5', '2001:db8:1::1']))
        p = self.auto('--dry-run')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('  1 203.0.113.10\n', p.stdout)
        self.assertIn('Would block: 1, Skipped: 4', p.stdout)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.rules(), [])

    def test_invalid_feeds_abort_before_mutation_including_dry_run(self):
        self.log.write_text(self.line())
        entries = [{}, {'prefixes': []}, {'prefixes': [None]},
                   {'prefixes': [{'ipv4Prefix': 'bad'}]},
                   {'prefixes': [{'ipv4Prefix': '2001:db8::/32'}]},
                   {'prefixes': [{'ipv4Prefix': '192.0.2.0/24'}]},
                   {'prefixes': [{'ipv4Prefix': True}]},
                   {'prefixes': [{'ipv4Prefix': '192.0.2.0/24', 'ipv6Prefix': '::/0'}]}]
        for feed in entries:
            for flags in [(), ('--dry-run',)]:
                with self.subTest(feed=feed, flags=flags):
                    (self.root / 'feed.json').write_text(json.dumps(feed))
                    p = self.auto(*flags)
                    self.assertNotEqual(p.returncode, 0)
                    self.assertIn('Googlebot', p.stderr)
                    self.assertEqual(self.calls(), [])

    def test_download_failure_aborts(self):
        self.log.write_text(self.line())
        p = self.auto(CURL_FAIL='1')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_rotations_combined_formats_and_ipv6_normalization(self):
        self.log.write_text(self.line() + self.line(age=30) + self.line(age=-30))
        Path(str(self.log) + '.1').write_text(self.line())
        with gzip.open(str(self.log) + '.2.gz', 'wt') as f:
            f.write(self.line())
        Path(str(self.log) + '-20261114').write_text(self.line())
        Path(str(self.log) + '.backup').write_text(self.line())
        p = self.run_tool('--autoblock', '10', '4', '--dry-run')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('  4 203.0.113.10\n', p.stdout)
        self.log.write_text(self.line('2001:db8:2::1') + self.line('2001:0db8:0002::1'))
        p = self.run_tool('--autoblock', '10', '2')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.rules('6'), [self.rule('2001:db8:2::1/128', web=True)])

    def test_corrupt_rotated_log_is_an_error(self):
        Path(str(self.log) + '.1.gz').write_text('not gzip')
        p = self.auto('--dry-run')
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn('No offenders found', p.stdout)

    def test_invalid_arguments_fail(self):
        for minutes, threshold in [('bad', '1'), ('0', '1'), ('1', '-1'), ('1', '0'), ('1.5', '1')]:
            with self.subTest(minutes=minutes, threshold=threshold):
                p = self.run_tool('--autoblock', minutes, threshold, '--dry-run')
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('positive integers', p.stderr)
        for args in [('203.0.113.10', 'extra'), ('--list', '4', 'extra'),
                     ('--autoblock', '10', '1', '--log'), ('--unblock', 'invalid')]:
            with self.subTest(args=args):
                self.assertNotEqual(self.run_tool(*args).returncode, 0)

    def test_log_override_and_scan_errors(self):
        alternate = self.root / 'apache_access_log'
        alternate.write_text(self.line())
        p = self.auto('--dry-run', '--log', str(alternate))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('Would block: 1', p.stdout)
        p = self.auto('--log', str(self.root / 'missing'))
        self.assertNotEqual(p.returncode, 0)
        # A matching directory causes an open error even when tests run as root.
        Path(str(self.log) + '.1').mkdir()
        p = self.auto()
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn('No offenders found', p.stdout)

    def test_unblock_removes_both_scopes_and_duplicates(self):
        unrelated = self.rule('203.0.113.11/32', web=True)
        self.set_rules([self.rule(), self.rule(), self.rule(web=True), unrelated])
        p = self.run_tool('--unblock', '203.0.113.10')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('removed 3 rule(s)', p.stdout)
        self.assertEqual(self.rules(), [unrelated])

    def test_unblock_failure_is_reported(self):
        self.set_rules([self.rule()])
        p = self.run_tool('--unblock', '203.0.113.10', DELETE_FAIL='1')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.rules(), [self.rule()])

    def test_unblock_saves_successes_when_another_argument_is_invalid(self):
        self.command('netfilter-persistent')
        self.set_rules([self.rule()])
        p = self.run_tool('--unblock', '203.0.113.10', 'invalid')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.rules(), [])
        self.assertIn(['netfilter-persistent', 'save'], self.calls())

    def test_help_and_missing_firewall_binary(self):
        p = self.run_tool('--help')
        self.assertEqual(p.returncode, 0)
        self.assertNotIn('\\n', p.stdout)
        self.assertIn('ALL services', p.stdout)
        (self.bin / 'iptables').unlink()
        p = self.run_tool('--list', '4')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('not found', p.stderr)

    def test_list_retains_scope_and_survives_lookup_errors(self):
        self.set_rules([self.rule(), self.rule(web=True)])
        p = self.run_tool('--list', '4', GEO='<html>unavailable</html>')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('all traffic', p.stdout)
        self.assertIn('--dports 80,443', p.stdout)
        self.assertIn('(unknown)', p.stdout)
        self.assertIn('(unresolved)', p.stdout)
        self.assertIn('-- total: 2', p.stdout)
        p = self.run_tool('--list', '4', READ_FAIL='1')
        self.assertNotEqual(p.returncode, 0)

    def test_allowlist_overlap_and_forward_confirmed_dns(self):
        self.allow.write_text('203.0.113.10\n')
        p = self.run_tool('203.0.113.0/24')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('protected', p.stdout)
        self.assertEqual(self.rules(), [])
        self.allow.write_text('*.example.com\n')
        self.log.write_text(self.line('2001:db8:2::1'))
        p = self.auto('--dry-run', PTR='client.example.com', FORWARD='2001:0db8:0002::1')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('Would block: 0, Skipped: 1', p.stdout)
        p = self.auto('--dry-run', PTR='client.example.com', FORWARD='2001:db8:3::1')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('Would block: 1, Skipped: 0', p.stdout)


if __name__ == '__main__':
    unittest.main()
