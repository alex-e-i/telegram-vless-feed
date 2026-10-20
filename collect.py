#!/usr/bin/env python3
"""Collect public proxy URIs from Telegram web previews. Python stdlib only."""
import argparse
import html
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

SCHEMES = ('vless', 'vmess', 'trojan', 'ss', 'hysteria2', 'hy2')
URI_RE = re.compile(r'(?i)(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s<>"\'`]+')
VALID_CHANNEL = re.compile(r'^[A-Za-z][A-Za-z0-9_]{4,31}$')
MAX_BYTES = 5_000_000


def extract(body):
    # Telegram previews may HTML-escape & and include links in href attributes.
    decoded = html.unescape(body)
    # Tags are boundaries; preserve link attributes in original HTML for href-based URIs.
    candidates = URI_RE.findall(decoded)
    found = []
    for candidate in candidates:
        candidate = re.split(r'[<>\s"\'`]', candidate, 1)[0]
        candidate = candidate.rstrip('.,;)]}')
        # If an HTML attribute was accidentally captured, discard suffix.
        candidate = re.split(r'(?i)(?:&quot;|&lt;|&gt;)', candidate, 1)[0]
        try:
            parts = urlsplit(candidate)
            if parts.scheme.lower() not in SCHEMES or not parts.netloc:
                continue
            if len(candidate) > 4096:
                continue
        except ValueError:
            continue
        found.append(candidate)
    return found


def fetch(channel, timeout):
    req = urllib.request.Request(
        f'https://t.me/s/{channel}',
        headers={'User-Agent': 'Mozilla/5.0 (compatible; PublicFeedCollector/1.0)',
                 'Accept': 'text/html'},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f'HTTP {resp.status}')
        data = resp.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise RuntimeError('Response exceeds 5 MB')
        return data.decode('utf-8', errors='replace')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--channels', default='channels.txt')
    ap.add_argument('--output', default='subs.txt')
    ap.add_argument('--report', default='report.json')
    ap.add_argument('--timeout', type=int, default=20)
    args = ap.parse_args()
    channel_path = Path(args.channels)
    if not channel_path.exists():
        raise SystemExit(f'No {channel_path}: add public channel usernames, one per line')
    channels = []
    for line in channel_path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        line = line.removeprefix('https://t.me/s/').removeprefix('https://t.me/')
        line = line.lstrip('@').strip('/')
        if not VALID_CHANNEL.fullmatch(line):
            print(f'Skipping invalid channel: {line!r}')
            continue
        if line not in channels:
            channels.append(line)
    if not channels:
        print('No channels configured. Add usernames to channels.txt.')
        return
    found = set()
    report = {'updated_at': datetime.now(timezone.utc).isoformat(), 'channels': {}, 'total': 0,
              'note': 'URI collection only; no live VPN or exit-country verification'}
    succeeded = 0
    for channel in channels:
        try:
            urls = extract(fetch(channel, args.timeout))
            found.update(urls)
            report['channels'][channel] = {'status': 'ok', 'extracted': len(urls)}
            succeeded += 1
            print(f'{channel}: {len(urls)} links')
        except (urllib.error.URLError, TimeoutError, RuntimeError, ValueError) as exc:
            report['channels'][channel] = {'status': 'error', 'message': str(exc)[:200]}
            print(f'{channel}: ERROR {exc}')
    if succeeded == 0:
        raise SystemExit('All channel fetches failed; preserving previous subscription')
    if not found:
        raise SystemExit('No URIs found; preserving previous subscription')
    output = Path(args.output)
    output.write_text('\n'.join(sorted(found)) + '\n', encoding='utf-8')
    report['total'] = len(found)
    Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'Wrote {len(found)} unique links to {output}')


if __name__ == '__main__':
    main()
