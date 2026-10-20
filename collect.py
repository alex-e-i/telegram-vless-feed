#!/usr/bin/env python3
"""Collect public Telegram proxy links; optionally verify actual proxy egress via sing-box."""
import argparse, base64, concurrent.futures, html, json, os, re, shutil, socket, subprocess, tempfile, time, urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

SCHEMES = ('vless', 'trojan', 'ss', 'vmess', 'hysteria2', 'hy2')
URI_RE = re.compile(r'(?i)(?:vless|trojan|ss|vmess|hysteria2|hy2)://[^\s<>"\'`]+')
VALID_CHANNEL = re.compile(r'^[A-Za-z][A-Za-z0-9_]{4,31}$')

def extract(body):
    results = []
    for candidate in URI_RE.findall(html.unescape(body)):
        candidate = re.split(r'[<>\s"\'`]', candidate, 1)[0].rstrip('.,;)]}')
        try:
            p = urlsplit(candidate)
            if p.scheme.lower() in SCHEMES and p.netloc and len(candidate) <= 4096:
                results.append(candidate)
        except ValueError:
            pass
    return results

def fetch(channel, timeout):
    req = urllib.request.Request(f'https://t.me/s/{channel}', headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html'})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f'HTTP {response.status}')
        data = response.read(5_000_001)
        if len(data) > 5_000_000:
            raise RuntimeError('Page exceeds 5MB')
        return data.decode('utf-8', errors='replace')

def decode_ss(uri):
    # Supports both ss://base64(method:password)@host:port and plaintext userinfo.
    value = uri[5:].split('#', 1)[0].split('?', 1)[0]
    if '@' not in value:
        value = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)).decode()
    credentials, hostport = value.rsplit('@', 1)
    if ':' not in credentials:
        credentials = base64.urlsafe_b64decode(credentials + '=' * (-len(credentials) % 4)).decode()
    method, password = unquote(credentials).split(':', 1)
    hp = urlsplit('ss://' + hostport)
    if not hp.hostname or not hp.port:
        raise ValueError('Invalid SS endpoint')
    return {'type': 'shadowsocks', 'server': hp.hostname, 'server_port': hp.port, 'method': method, 'password': password}

def outbound(uri):
    p = urlsplit(uri)
    if p.scheme == 'ss':
        return decode_ss(uri)
    if p.scheme not in ('vless', 'trojan') or not p.hostname or not p.port or not p.username:
        raise ValueError('Unsupported protocol or incomplete endpoint')
    q = {k.lower(): v[-1] for k, v in parse_qs(p.query).items()}
    obj = {'type': p.scheme, 'server': p.hostname, 'server_port': p.port}
    if p.scheme == 'vless':
        obj.update(uuid=unquote(p.username), flow=q.get('flow', ''))
    else:
        obj['password'] = unquote(p.username)
    security = q.get('security', 'none').lower()
    if security in ('tls', 'reality'):
        tls = {'enabled': True, 'server_name': q.get('sni') or q.get('servername') or p.hostname, 'insecure': q.get('allowinsecure', '0') == '1'}
        if q.get('alpn'):
            tls['alpn'] = q['alpn'].split(',')
        if q.get('fp'):
            tls['utls'] = {'enabled': True, 'fingerprint': q['fp']}
        if security == 'reality':
            if not q.get('pbk'):
                raise ValueError('Reality public key missing')
            tls['reality'] = {'enabled': True, 'public_key': q['pbk'], 'short_id': q.get('sid', '')}
        obj['tls'] = tls
    elif security not in ('none', ''):
        raise ValueError('Unsupported security')
    network = q.get('type', 'tcp').lower()
    if network == 'ws':
        transport = {'type': 'ws', 'path': unquote(q.get('path', '/'))}
        if q.get('host'):
            transport['headers'] = {'Host': q['host']}
        obj['transport'] = transport
    elif network == 'grpc':
        obj['transport'] = {'type': 'grpc', 'service_name': q.get('servicename', '')}
    elif network not in ('tcp', ''):
        raise ValueError('Unsupported transport')
    return obj

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def verify(uri, sing_box, timeout, test_url):
    try:
        ob = outbound(uri)
    except Exception as exc:
        return (uri, 'unsupported', str(exc)[:120])
    port = free_port()
    cfg = {'log': {'level': 'error'}, 'inbounds': [{'type': 'socks', 'tag': 'local', 'listen': '127.0.0.1', 'listen_port': port}],
           'outbounds': [dict(ob, tag='proxy')] , 'route': {'final': 'proxy'}}
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'config.json'
        path.write_text(json.dumps(cfg), encoding='utf-8')
        process = subprocess.Popen([sing_box, 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(0.35)
            if process.poll() is not None:
                return (uri, 'failed', 'sing-box exited')
            cmd = ['curl', '--silent', '--show-error', '--fail', '--max-time', str(timeout), '--socks5-hostname', f'127.0.0.1:{port}', '-o', os.devnull, '-w', '%{http_code}', test_url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
            if result.returncode == 0 and result.stdout.strip() in ('200', '204'):
                return (uri, 'ok', result.stdout.strip())
            return (uri, 'failed', (result.stderr.strip() or result.stdout.strip())[:120])
        except (OSError, subprocess.TimeoutExpired) as exc:
            return (uri, 'failed', str(exc)[:120])
        finally:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--channels', default='channels.txt')
    ap.add_argument('--output', default='subs.txt')
    ap.add_argument('--report', default='report.json')
    ap.add_argument('--timeout', type=int, default=10)
    ap.add_argument('--workers', type=int, default=8)
    ap.add_argument('--verify', action='store_true', help='Require real HTTP egress via sing-box')
    ap.add_argument('--sing-box', default='sing-box')
    ap.add_argument('--test-url', default='https://www.gstatic.com/generate_204')
    args = ap.parse_args()
    channels = []
    for line in Path(args.channels).read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        line = line.removeprefix('https://t.me/s/').removeprefix('https://t.me/').lstrip('@').strip('/')
        if VALID_CHANNEL.fullmatch(line) and line not in channels:
            channels.append(line)
        else:
            print(f'Skipping invalid/duplicate channel: {line}')
    if not channels:
        raise SystemExit('No channels configured')
    report = {'updated_at': datetime.now(timezone.utc).isoformat(), 'channels': {}, 'verification_enabled': args.verify}
    found = set()
    success = 0
    for channel in channels:
        try:
            urls = extract(fetch(channel, args.timeout))
            found.update(urls)
            report['channels'][channel] = {'status': 'ok', 'extracted': len(urls)}
            success += 1
            print(f'{channel}: {len(urls)} links')
        except Exception as exc:
            report['channels'][channel] = {'status': 'error', 'message': str(exc)[:150]}
            print(f'{channel}: ERROR {exc}')
    if success == 0:
        raise SystemExit('All Telegram fetches failed; preserving last published file')
    if not found:
        raise SystemExit('No URIs found; preserving last published file')
    report['collected_unique'] = len(found)
    if args.verify:
        if not shutil.which(args.sing_box) or not shutil.which('curl'):
            raise SystemExit('Verification requires sing-box and curl')
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(args.workers, 16))) as pool:
            results = list(pool.map(lambda uri: verify(uri, args.sing_box, args.timeout, args.test_url), sorted(found)))
        accepted = sorted(uri for uri, status, _ in results if status == 'ok')
        report['verification'] = {'ok': len(accepted), 'failed': sum(s == 'failed' for _, s, _ in results),
                                  'unsupported': sum(s == 'unsupported' for _, s, _ in results)}
        print('Verification:', report['verification'])
    else:
        accepted = sorted(found)
    report['published'] = len(accepted)
    # Empty file is intentional when every tested proxy fails; never publish unverified nodes.
    Path(args.output).write_text(('\n'.join(accepted) + '\n') if accepted else '', encoding='utf-8')
    Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'Published {len(accepted)} of {len(found)} collected nodes')

if __name__ == '__main__':
    main()
