#!/usr/bin/env python3
"""scout_pc.py — the patch state of THIS PC, posted to Scout's private PC topic (Zorin / Ubuntu / Debian; stdlib only).

  python3 scout_pc.py --install <topic>   save the topic, post once, and add a cron entry (every 6 h + 2 min after boot)
  python3 scout_pc.py --print             show what would be posted
  python3 scout_pc.py                     post once (the topic from ~/.config/scout_pc.topic)

Read-only on the PC: hostname, OS, kernel running and installed, security updates waiting (apt), reboot needed.
The home Scout reads the topic, warns when a PC lags, and tells which PCs still need a fix once Ubuntu ships it."""
import glob, json, os, platform, re, socket, subprocess, sys, time, urllib.request

NTFY = 'https://ntfy.sh'
TOPIC_FILE = os.path.expanduser('~/.config/scout_pc.topic')


def _run(cmd, timeout=90):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ''


def collect():
    osr = {}
    try:
        for line in open('/etc/os-release'):
            if '=' in line:
                k, v = line.rstrip('\n').split('=', 1)
                osr[k] = v.strip('"')
    except OSError:
        pass
    kern = platform.release()                                            # 7.0.0-42-generic
    installed = []
    for l in _run(['dpkg-query', '-W', '-f=${Package} ${Version} ${db:Status-Abbrev}\n', 'linux-image-*']).splitlines():
        p = l.split()
        if len(p) >= 3 and p[2].startswith('ii') and re.match(r'linux-image-\d', p[0]):
            installed.append(p[0].replace('linux-image-', ''))           # 7.0.0-42-generic
    up = _run(['apt', 'list', '--upgradable'])
    sec = sorted({l.split('/')[0] for l in up.splitlines() if '-security' in l})
    allup = sorted({l.split('/')[0] for l in up.splitlines() if '/' in l and not l.startswith('Listing')})
    lists = glob.glob('/var/lib/apt/lists/*Packages') or glob.glob('/var/lib/apt/lists/*')
    lists_age_h = round((time.time() - max(os.path.getmtime(f) for f in lists)) / 3600, 1) if lists else None
    reboot_h = None
    if os.path.exists('/var/run/reboot-required'):
        reboot_h = round((time.time() - os.path.getmtime('/var/run/reboot-required')) / 3600, 1)
    try:
        uptime_h = round(float(open('/proc/uptime').read().split()[0]) / 3600, 1)
    except (OSError, ValueError):
        uptime_h = None
    return {'host': socket.gethostname(), 'os': osr.get('PRETTY_NAME', 'Linux'), 'codename': osr.get('UBUNTU_CODENAME') or osr.get('VERSION_CODENAME', ''),
            'kernel': kern, 'kernels_installed': sorted(installed)[-4:], 'sec_updates': sec[:40], 'updates': len(allup),
            'lists_age_h': lists_age_h, 'reboot_h': reboot_h, 'uptime_h': uptime_h, 'v': 1, 't': int(time.time())}


def post(topic, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(f"{NTFY}/{topic}", data=body, method='POST',
                                 headers={'Title': f"pc {data['host']}", 'Priority': 'min', 'Tags': 'computer',
                                          'Content-Type': 'application/json', 'User-Agent': 'scout-pc/1'})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status


def install(topic):
    os.makedirs(os.path.dirname(TOPIC_FILE), exist_ok=True)
    with open(TOPIC_FILE, 'w') as f:
        f.write(topic.strip() + '\n')
    os.chmod(TOPIC_FILE, 0o600)
    me = os.path.abspath(__file__)
    line1 = f"17 */6 * * * /usr/bin/python3 {me} >/dev/null 2>&1"
    line2 = f"@reboot sleep 120 && /usr/bin/python3 {me} >/dev/null 2>&1"
    cur = _run(['crontab', '-l'])
    keep = [l for l in cur.splitlines() if 'scout_pc.py' not in l]
    new = '\n'.join(keep + [line1, line2]) + '\n'
    subprocess.run(['crontab', '-'], input=new, text=True, check=True)
    print(f"topic saved in {TOPIC_FILE}; cron: every 6 h and after boot")


if __name__ == '__main__':
    args = sys.argv[1:]
    if args[:1] == ['--print']:
        print(json.dumps(collect(), indent=1))
        sys.exit(0)
    if args[:1] == ['--install'] and len(args) == 2:
        install(args[1])
    try:
        topic = open(TOPIC_FILE).read().strip()
    except OSError:
        sys.exit(f"no topic yet: python3 {os.path.basename(__file__)} --install <topic>")
    d = collect()
    print(f"{d['host']}: {d['os']}, kernel {d['kernel']}, {len(d['sec_updates'])} security update(s) waiting"
          + (f", reboot needed {d['reboot_h']} h" if d['reboot_h'] is not None else '') + f" → ntfy {post(topic, d)}")
