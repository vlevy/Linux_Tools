"""Offline status-report tests; all firewall, HTTP and DNS commands are mocks."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from datetime import datetime


SOURCE = Path(__file__).resolve().parents[1] / 'busy_clients'
MOCK = r'''#!/usr/bin/python3
import json, os, sys
from pathlib import Path
root = Path(os.environ['FIXTURES'])
name, args = Path(sys.argv[0]).name, sys.argv[1:]
if name in ('iptables', 'ip6tables'):
    if os.environ.get('FIREWALL_FAIL') == name:
        sys.exit(4)
    assert '-S' in args, 'Tests must never change rules'
    print((root / (name + '.rules')).read_text())
elif name == 'curl':
    if '--output' in args:
        google = 'common-crawlers.json' in args[-1]
        if google and os.environ.get('FEED_FAIL'):
            sys.exit(28)
        content = (root / 'feed.json').read_text() if google else 'User-agent: *\nDisallow: /private\n'
        Path(args[args.index('--output') + 1]).write_text(content)
        if not google:
            print('200', end='')
    else:
        print('{}')
elif name == 'getent':
    if args[0] == 'hosts' and os.environ.get('PTR'):
        print(args[1], os.environ['PTR'])
    elif args[0] == 'ahosts' and os.environ.get('FORWARD'):
        print(os.environ['FORWARD'], 'STREAM fixture')
    else:
        sys.exit(2)
elif name == 'host':
    sys.exit(1)
else:
    raise AssertionError(name)
'''


class BusyClientsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='busy-clients-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name in ('iptables', 'ip6tables', 'curl', 'getent', 'host'):
            path = self.bin / name
            path.write_text(MOCK)
            path.chmod(0o700)
        source = SOURCE.read_text()
        start = source.index('find_cmd() {')
        end = source.index('# Write source CIDRs', start)
        source = source[:start] + '''find_cmd() {
  [ -x "$FIXTURES/bin/$1" ] || return 1
  printf '%s\\n' "$FIXTURES/bin/$1"
}
''' + source[end:]
        # Only the temporary copy bypasses sudo; binaries have no real fallback.
        self.script = self.root / 'busy_clients'
        self.script.write_text(source.replace('${EUID:-$(id -u)}', '0'))
        self.log = self.root / 'access.log'
        self.log.write_text('')
        self.allow = self.root / 'allow'
        self.allow.write_text('35.174.27.227\n10.0.0.7\n70.23.240.24\n74.110.199.43\n')
        self.robots = self.root / 'robots.txt'
        self.robots.write_text('User-agent: *\nDisallow: /private\n')
        self.feed = {'prefixes': [{'ipv4Prefix': '192.0.2.0/24'},
                                  {'ipv6Prefix': '2001:db8:1::/48'}]}
        (self.root / 'feed.json').write_text(json.dumps(self.feed))
        (self.root / 'iptables.rules').write_text('-P INPUT ACCEPT\n-A INPUT -s 203.0.113.0/24 -j DROP\n')
        (self.root / 'ip6tables.rules').write_text('-P INPUT ACCEPT\n-A INPUT -s 2001:db8:2::/48 -j DROP\n')
        self.env = {**os.environ, 'FIXTURES': str(self.root),
                    'PATH': f'{self.bin}:/usr/bin:/bin', 'XDG_CACHE_HOME': str(self.root / 'cache'),
                    'ACCESS_LOG': str(self.log), 'ROBOTS_FILE': str(self.robots),
                    'ALLOWLIST_FILE': str(self.allow)}

    def lines(self, *addresses, path='/private'):
        stamp = datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000')
        self.log.write_text(''.join(f'{ip} - - [{stamp}] "GET {path} HTTP/1.1" 200 1 "-" "fixture"\n' for ip in addresses))

    def run_tool(self, *args, **env):
        return subprocess.run(['bash', str(self.script), *args],
                              env={**self.env, **env}, capture_output=True, text=True, timeout=10)

    def statuses(self, **env):
        p = self.run_tool('--list', '1', **env)
        self.assertEqual(p.returncode, 0, p.stderr)
        return {row.split('\t')[0]: row.split('\t')[3] for row in p.stdout.splitlines()}

    def test_all_three_values_and_protection_sources(self):
        expected = {'35.174.27.227': 'protected', '10.0.0.7': 'protected',
                    '70.23.240.24': 'protected', '74.110.199.43': 'protected',
                    '127.0.0.1': 'protected', '::1': 'protected',
                    '192.0.2.9': 'protected', '2001:db8:1::3': 'protected',
                    '203.0.113.9': 'blocked', '2001:db8:2::1': 'blocked',
                    '198.51.100.9': 'open', '2001:db8:3::1': 'open'}
        self.lines(*expected)
        self.assertEqual(self.statuses(), expected)

    def test_existing_block_takes_precedence_over_exception(self):
        self.lines('70.23.240.24')
        (self.root / 'iptables.rules').write_text('-A INPUT -s 70.23.240.0/24 -j DROP\n')
        self.assertEqual(self.statuses(), {'70.23.240.24': 'blocked'})

    def test_allowlist_comments_and_cidr(self):
        self.allow.write_text('# comment\n198.51.100.0/24 # trusted subnet\n')
        self.lines('198.51.100.9')
        self.assertEqual(self.statuses(), {'198.51.100.9': 'protected'})

    def test_hostname_globs_require_forward_confirmation(self):
        self.allow.write_text('*.example.com\n')
        self.lines('2001:db8:3::1')
        self.assertEqual(self.statuses(PTR='Client.Example.COM.', FORWARD='2001:0db8:0003::1'),
                         {'2001:db8:3::1': 'protected'})
        self.assertEqual(self.statuses(PTR='client.example.com', FORWARD='2001:db8:4::1'),
                         {'2001:db8:3::1': 'open'})
        self.assertEqual(self.statuses(), {'2001:db8:3::1': 'open'})

    def test_table_header_and_sorting_are_preserved(self):
        self.lines('198.51.100.9', '198.51.100.9', '70.23.240.24')
        p = self.run_tool('1')
        self.assertEqual(p.returncode, 0, p.stderr)
        header = next(line for line in p.stdout.splitlines() if line.startswith('IP '))
        self.assertIn('status', header.split())
        self.assertNotIn('blocked', header.split())
        rows = [line.split() for line in p.stdout.splitlines() if line.startswith(('198.', '70.'))]
        self.assertEqual([row[3] for row in rows], ['open', 'protected'])
        self.assertEqual(rows[0][1:3], ['2', '2'])
        p = self.run_tool('--list', '--sort', 'total', '1')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.splitlines()[0].split('\t')[:4], ['198.51.100.9', '2', '2', 'open'])

    def test_unreadable_firewall_fails_instead_of_reporting_open(self):
        self.lines('198.51.100.9')
        for name in ('iptables', 'ip6tables'):
            with self.subTest(name=name):
                p = self.run_tool('--list', '1', FIREWALL_FAIL=name)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('cannot determine status', p.stderr)
                self.assertEqual(p.stdout, '')

    def test_missing_allowlist_fails(self):
        self.lines('70.23.240.24')
        p = self.run_tool('--list', '1', ALLOWLIST_FILE=str(self.root / 'absent'))
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('allowlist', p.stderr)
        self.assertEqual(p.stdout, '')

    def test_invalid_or_unavailable_crawler_feed_fails(self):
        self.lines('198.51.100.9')
        for feed in ({}, {'prefixes': []}, {'prefixes': [None]},
                     {'prefixes': [{'ipv4Prefix': 'bad'}]},
                     {'prefixes': [{'ipv4Prefix': '192.0.2.0/24'}]},
                     {'prefixes': [{'ipv4Prefix': True}]},
                     {'prefixes': [{'ipv4Prefix': '::/0'}]}):
            with self.subTest(feed=feed):
                (self.root / 'feed.json').write_text(json.dumps(feed))
                p = self.run_tool('--list', '1')
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('cannot determine protection status', p.stderr)
                self.assertEqual(p.stdout, '')
        p = self.run_tool('--list', '1', FEED_FAIL='1')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(p.stdout, '')

    def test_live_robots_fetch_path_with_mock_http(self):
        self.lines('70.23.240.24')
        self.assertEqual(self.statuses(ROBOTS_FILE=''), {'70.23.240.24': 'protected'})

    def test_invalid_sources_ignored_and_ipv6_spellings_combined(self):
        self.lines('invalid', '2001:db8:3::1', '2001:0db8:0003::1')
        p = self.run_tool('--list', '1')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.splitlines()[0].split('\t')[:4], ['2001:db8:3::1', '2', '2', 'open'])
        self.assertEqual(len(p.stdout.splitlines()), 1)


if __name__ == '__main__':
    unittest.main()
