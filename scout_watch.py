#!/usr/bin/env python3
"""scout_watch — the outside eye on Scout (S5, standalone). Run by cron every 15 minutes.

Scout cannot report its own death, so this small script checks from outside: is the heartbeat fresh, is the service
running, is the disk filling up? It warns once per incident through the same ntfy topic, and once when Scout is back.
It imports nothing from scout.py, so a broken scout.py cannot break the watcher. Read-only: it never restarts anything.
"""
import configparser, datetime, json, os, shutil, subprocess, sys, time, urllib.parse, urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
cfg = configparser.ConfigParser()
cfg.read(os.path.join(BASE, 'data', 'scout.conf'))
TOPIC  = cfg['ntfy']['topic']
SERVER = cfg['ntfy']['server']
DATA   = os.path.dirname(cfg['scout']['seen_db'])
HEARTBEAT = os.path.join(DATA, 'heartbeat.json')
STATE  = os.path.join(DATA, 'watch_state.json')


def push(title, body, priority='high'):
    url = f"{SERVER}/{TOPIC}?" + urllib.parse.urlencode({'title': title, 'priority': priority, 'tags': 'eyes'})
    req = urllib.request.Request(url, data=body.encode('utf-8'), method='POST')
    try:
        urllib.request.urlopen(req, timeout=15).read()
        return True
    except Exception as e:                       # no internet: try again at the next run
        print(f"push failed: {e}", file=sys.stderr)
        return False


def load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def service_state():
    try:
        out = subprocess.run(['systemctl', 'show', 'scout', '-p', 'ActiveState', '-p', 'SubState', '-p', 'NRestarts'],
                             capture_output=True, text=True, timeout=10).stdout
        return dict(l.split('=', 1) for l in out.splitlines() if '=' in l)
    except Exception:
        return {}


def last_log_lines(n=3):
    try:
        out = subprocess.run(['journalctl', '-u', 'scout', '-n', str(n), '--no-pager', '-o', 'cat'],
                             capture_output=True, text=True, timeout=10).stdout.strip()
        return out[-600:]
    except Exception:
        return ''


def main():
    now = time.time()
    try:
        uptime = float(open('/proc/uptime').read().split()[0])
    except OSError:
        uptime = 3600
    if uptime < 20 * 60:                         # just booted: Scout is still starting, give it time
        return
    state = load(STATE, {})
    hb = load(HEARTBEAT, None)
    svc = service_state()
    fast = int((hb or {}).get('fast_minutes', 20))
    age = now - float(hb['ts']) if hb else None
    problems = []
    if svc.get('ActiveState') and svc.get('ActiveState') != 'active':
        problems.append(f"service is {svc.get('ActiveState')}/{svc.get('SubState')}")
    if hb is None:
        if svc.get('ActiveState') != 'active':      # running but no file = a Scout older than v3.0, not a fault
            problems.append("no heartbeat file")
    elif hb.get('stage') == 'stopped':
        problems.append(f"stopped at {hb.get('time')}")
    elif hb.get('stage') == 'offline':
        pass                                     # the internet is down: Scout knows and waits; nothing to add
    elif age > (fast + 45) * 60:
        problems.append(f"silent since {hb.get('time')} ({age / 60:.0f} min, stage '{hb.get('stage')}')")

    if problems and not state.get('down_since'):
        body = ("Scout is not working: " + '; '.join(problems) + ".\n"
                f"Restarts so far: {svc.get('NRestarts', '?')}.\nLast log lines:\n{last_log_lines()}\n\n"
                "Check: sudo systemctl status scout   ·   journalctl -u scout -n 50")
        if push("Scout watch: Scout is down", body, priority='urgent'):
            state['down_since'] = now
            state['why'] = '; '.join(problems)
    elif not problems and state.get('down_since'):
        gone = (now - state['down_since']) / 60
        if push("Scout watch: Scout is back", f"Running again (stage '{hb.get('stage')}', heartbeat {hb.get('time')}). "
                f"It was reported down {gone:.0f} min ago: {state.get('why', '?')}.", priority='low'):
            state.pop('down_since', None)
            state.pop('why', None)

    free = shutil.disk_usage(DATA).free / 2**30
    today = datetime.date.today().isoformat()
    if free < 1.0 and state.get('disk_warned') != today:
        if push("Scout watch: disk almost full", f"Only {free:.2f} GB free where Scout keeps its data ({DATA}).",
                priority='high'):
            state['disk_warned'] = today

    state['last_run'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    tmp = STATE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(state, f)
    os.replace(tmp, STATE)


if __name__ == '__main__':
    main()
