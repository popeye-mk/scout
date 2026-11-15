#!/usr/bin/env python3
"""
Scout v3.6 — Passive threat intelligence, two lanes: early sources every 20 min, everything every 6 h
Sources: CISA KEV (all + filtered), CISA Alerts, CISA ICS,
         NVD published+modified+HIGH (EPSS enriched), MITRE CVEProject,
         CIRCL CVE, OSV.dev, CERT.be, Exploit-DB, BleepingComputer,
         TheHackersNews, SecurityWeek, SANS ISC, GitHub Advisory,
         GitHub PoC search, PoC-in-GitHub, Nuclei Templates, Vulhub,
         Reddit r/netsec, Reddit r/cybersecurity, PacketStorm,
         HackerNews Algolia, ZDI, MSRC, Rapid7, Cisco Talos, Unit 42,
         Tenable, AttackerKB, Product Releases, Sploitus,
         oss-security, Full-Disclosure, Bugtraq, Cisco-SA, Joomla-SA,
         NCSC-UK, JPCERT, CERT-FR, BSI-Germany, CERT-CC,
         Mandiant, CheckPoint, Securelist, CrowdStrike,
         AquaSec, Wiz, ESET, Sophos, Vulners, infosec.exchange
"""

import configparser, html, json, os, platform, re, sys, time, datetime, requests
import xml.etree.ElementTree as ET

try:
    sys.stdout.reconfigure(line_buffering=True)     # v2.2: journalctl shows [ALERT] lines live, not hours later
except Exception:
    pass
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get('SCOUT_CONF') or os.path.join(BASE_DIR, 'data', 'scout.conf')   # v3.2: cloud sets SCOUT_CONF

cfg = configparser.ConfigParser()
cfg.read(CONFIG_PATH)

NTFY_TOPIC  = cfg['ntfy']['topic']
NTFY_SERVER = cfg['ntfy']['server']
SEEN_DB     = cfg['scout']['seen_db']
MIN_CVSS    = float(cfg['scout']['min_cvss_score'])
INTERVAL    = int(cfg['scout']['check_interval_hours'])
USER_AGENT  = cfg['privacy']['user_agent']
KEYWORDS    = [k.strip().lower() for k in cfg['products']['keywords'].split(',')]
HEADERS     = {'User-Agent': USER_AGENT}
LOOKBACK    = 30

# GitHub (v2.2): without a token the API allows 60 calls per hour per address, and once that was spent the
# scout's seven GitHub checks said "nothing new" without a word (seen 2026-10-22). A token — free, no scopes —
# raises it to 5 000 per hour. Put it in scout.conf under [github]; it is sent only to api.github.com.
GITHUB_TOKEN = cfg.get('github', 'token', fallback='').strip()
GH_HEADERS   = dict(HEADERS, Accept='application/vnd.github+json')
if GITHUB_TOKEN:
    GH_HEADERS['Authorization'] = f"Bearer {GITHUB_TOKEN}"

# Product name variants — catches aliases the config keywords would miss
_ALIASES = {
    'php':            ['php-fpm', 'php8.', 'php7.', 'mod_php', 'php2shell'],
    'apache':         ['httpd', 'apache2', 'apache http', 'mod_ssl', 'mod_proxy', 'mod_cgi'],
    'cisco':          ['ios xe', 'ios xr', 'cisco asa', 'firepower', 'anyconnect', 'webex', 'meraki', 'nx-os', 'cisco rv'],
    'mikrotik':       ['routeros', 'winbox', 'mikro tik', 'rb951', 'chr '],
    'windows server': ['active directory', 'ntlm relay', 'kerberos', 'netlogon', 'smb exploit', 'iis exploit', 'rdp exploit', 'spoolsv'],
    'docker':         ['containerd', 'runc', 'moby', 'docker engine', 'docker compose'],
    'kubernetes':     ['k8s', 'kubectl', 'kubelet', 'kube-apiserver', 'etcd cve', 'helm exploit'],
    'postgresql':     ['psql', 'pg_dump', 'pg_hba'],
    'home assistant': ['hassio', 'hass.io', 'ha core', 'homeassistant', 'home-assistant', 'hassio'],
    'openssh':        ['sshd exploit', 'ssh rce', 'ssh vuln', 'openssh cve'],
    'fritz':          ['fritzbox', 'fritz!box', 'avm fritz'],
    'nginx':          ['nginx plus', 'nginx/1.', 'nginx proxy'],
    'joomla':         ['joomla!', 'com_content', 'joomla cms'],
    'ollama':         ['ollama api', 'ollama server', 'llm api exploit'],
    'debian':         ['apt exploit', 'dpkg vuln'],
    'ubuntu':         ['snap exploit', 'ubuntu lts', 'zorin', 'zorin os', 'linux mint'],   # v3.6: Ubuntu-based desktops
    # v2.2 — the house's own devices (seen on the Wi-Fi) and the rest of his stack (THREAT-BRIEF.md)
    'fortinet':       ['fortigate', 'fortios', 'forticlient'],
    'palo alto':      ['pan-os', 'globalprotect'],
    'vmware':         ['esxi', 'vcenter', 'vsphere'],
    'ubiquiti':       ['unifi'],
    'exchange server': ['microsoft exchange', 'exchange online', 'owa exploit'],
    'android':        ['android tv', 'google play', 'play store'],
    'eufy':           ['anker eufy', 'eufy security'],
    'tp-link':        ['tapo', 'kasa', 'omada'],
    'samsung':        ['smartthings', 'tizen', 'galaxy'],
    'google nest':    ['chromecast', 'nest hub', 'nest audio', 'nest mini'],
    'huawei':         ['sun2000', 'fusionsolar'],
    'xiaomi':         ['miui', 'hyperos', 'mi tv', 'redmi'],
    'espressif':      ['esp32', 'esp8266', 'esphome'],
    'node.js':        ['nodejs', 'npm package', 'npm supply chain'],
    'python':         ['pypi'],
    'linux kernel':   ['kernel exploit', 'kernel privilege'],
    # v2.3 — work stack
    'chrome':         ['chromium', 'stable channel update', 'google chrome'],
    'microsoft edge': ['edge browser', 'edge chromium'],
    'microsoft 365':  ['office 365', 'm365', 'o365'],
    'entra id':       ['entra', 'azure ad', 'azure active directory'],
    'microsoft defender': ['defender for endpoint', 'defender antivirus'],
    'sql server':     ['mssql'],
    'citrix':         ['netscaler', 'citrix adc', 'xenapp', 'citrix gateway'],
    'ivanti':         ['pulse secure', 'connect secure', 'ivanti epmm', 'mobileiron'],
    'check point':    ['checkpoint firewall', 'gaia os'],
    'hpe ilo':        ['idrac', 'integrated lights-out'],
    'adobe':          ['acrobat', 'adobe reader'],
    'screenconnect':  ['connectwise'],
    'atlassian':      ['confluence', 'jira', 'bitbucket'],
    'wordpress':      ['wp plugin', 'wordpress plugin', 'woocommerce'],
    'elasticsearch':  ['kibana', 'elastic stack'],
}

# Always alert on these regardless of product — signals active exploitation
_UNIVERSAL = [
    'actively exploited', 'exploited in the wild', 'zero-day exploit', '0-day', '0day exploit',
    'wormable', 'mass exploitation', 'nation-state', 'apt group exploit',
    'ransomware campaign', 'critical infrastructure attack', 'supply chain attack',
]

# Flat list used by matches() — built once at startup
_ALL_TERMS = list(KEYWORDS)
for _kw in KEYWORDS:
    _ALL_TERMS.extend(_ALIASES.get(_kw, []))

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

# Reset every cycle — tracks which sources mention each CVE for correlation
_cycle_cve_hits: dict = {}

REDDIT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'Accept': 'application/rss+xml, application/xml, text/xml',
}

ANTHROPIC_KEY = cfg.get('anthropic', 'api_key', fallback='').strip()
# v2.4: the model is a setting (default the current Opus; claude-haiku-5-5 is the cheap one), and at most this many
# AI briefings per cycle — the rest, and every alert when the key, the credit or the network is gone, carry the
# deterministic essentials instead (CVE ids, CVSS, your product, attack words, versions). Never "nothing".
ANTHROPIC_MODEL = cfg.get('anthropic', 'model', fallback='').strip() or 'claude-opus-5-5'
AI_MAX_PER_CYCLE = int(cfg.get('anthropic', 'max_per_cycle', fallback='30') or 30)
_ai_state = {'down_until': 0.0, 'reason': '', 'used': 0, 'told': False}

# v2.5 (S1): two lanes. The fast lane re-reads the early, cheap sources every FAST_MINUTES; the slow lane reads the
# rest every check_interval_hours. A fast feed that answers 429 moves to the slow lane for the rest of the day.
FAST_MINUTES = max(5, int(cfg.get('lanes', 'fast_minutes', fallback='20') or 20))
_DEFAULT_FAST_RSS = ('oss-security, Full-Disclosure, Bugtraq, Exploit-DB, Cisco-SA, Joomla-SA, MSRC, PaloAlto-SA, '
                     'Fortinet-PSIRT, Debian-DSA, Ubuntu-USN, RedHat-SA, CERT-EU, CERT.be, CISA-Alerts, '
                     'BleepingComputer, TheHackersNews, SecurityWeek, Reddit-netsec, Reddit-cybersec, Linux-kernel-CVE')
FAST_RSS = {n.strip() for n in (cfg.get('lanes', 'fast_rss', fallback='') or _DEFAULT_FAST_RSS).split(',') if n.strip()}
FAST_CHECK_NAMES = {'CISA-KEV', 'HackerNews', 'Mastodon', 'GitHub-PoCs', 'PoC-in-GitHub', 'GoogleNews', 'Telegram', 'MSRC-CVRF'}
# v2.7, design rule: "think like a system engineer — all info is welcome". Advisory feeds of vendors and distributions
# are passed through IN FULL: an item about your gear still alerts at once; every other item goes into the digest
# (the zlib or OpenVPN USN a sysadmin wants to know about, even when it isn't on the product list).
_DEFAULT_FULL = ('Ubuntu-USN, Debian-DSA, Debian-DLA, RedHat-SA, AlmaLinux, Linux-kernel-CVE, oss-security, Exploit-DB, '
                 'ZDI, Cisco-SA, PaloAlto-SA, Fortinet-PSIRT, Joomla-SA, Jenkins-SA, GitLab-SR, CERT-EU, CERT.be, '
                 'NCSC-NL, CISA-Alerts, CISA-ICS')
FULL_FEEDS = {n.strip() for n in (cfg.get('lanes', 'full_feeds', fallback='') or _DEFAULT_FULL).split(',') if n.strip()}
NO_CONFIRM = {'Linux-kernel-CVE'}    # the kernel's own CVE list is a database, not an independent source
_KERNEL_NET_RE = re.compile(r'(?i)\b(?:net|tcp|udp|ipv[46]|netfilter|nf_\w+|bluetooth|wifi|wlan|mac80211|ksmbd|smb|cifs|'
                            r'nfsd?|sctp|xfrm|tls|bpf|vsock|tipc|rds|ppp|can)\b')
_demoted: dict = {}          # fast RSS source -> the day it was moved to the slow lane (it answered 429)
_validators: dict = {}       # url -> (ETag, Last-Modified): an unchanged feed answers 304 and costs nothing

# Tracks errors since the last slow cycle: name -> [count, last message]
_cycle_errors: dict = {}
# Consecutive failure counts per source name; persists across cycles
_fail_counts: dict  = {}

# ── helpers ───────────────────────────────────────────────────────────────────

def load_seen():
    if os.path.exists(SEEN_DB):
        with open(SEEN_DB) as f:
            return json.load(f)
    return {}

def save_seen(seen):
    os.makedirs(os.path.dirname(os.path.abspath(SEEN_DB)), exist_ok=True)   # a fresh cloud runner has no data/ yet
    tmp = SEEN_DB + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(seen, f)
    os.replace(tmp, SEEN_DB)                        # never a half-written seen.json after a kill or a power cut

OUTBOX = os.path.join(os.path.dirname(SEEN_DB), 'outbox.jsonl')

def _ntfy_push(params, body):
    """v3.6: a 4xx from ntfy means the request is wrong (a bad button, not an outage): send again without the
    buttons so the alert still reaches the phone, instead of parking it in the outbox for ever."""
    try:
        _ntfy_send(params, body)
    except requests.HTTPError as e:
        if e.response is None or not 400 <= e.response.status_code < 500 or 'actions' not in params:
            raise
        print(f"[ALERT] ntfy refused the buttons ({e.response.text[:120]}) — sent without them")
        _ntfy_send({k: v for k, v in params.items() if k != 'actions'}, body)

def _ntfy_send(params, body):
    # Title as a query parameter: HTTP headers are latin-1 only, so "—" or emoji in a title failed the send
    r = requests.post(f"{NTFY_SERVER}/{NTFY_TOPIC}", data=body.encode('utf-8'), params=params, timeout=15)
    r.raise_for_status()

# v3.6: an area icon in front of every title (ntfy turns the tag into an emoji), so the phone list can be scanned by
# eye: 🐧 Linux, 🐍 Python & code, 🪟 Windows/Microsoft, 🏠 home devices, 🌐 network gear, 🌍 web servers, 📋 reports.
# The urgency dot (🔴🟠🟡⚪) inside the message stays what it was. The title counts three times, the body once.
# 🏠 in front of it = the item touches something on the HOME list ([products] home in scout.conf): read those first.
_DOMAIN_ICONS = [
    ('clipboard', ['6 h report', 'morning brief', 'evening brief', 'weekly letter', 'patch tuesday', 'scout daily',
                   'scout:', 'home scout is back', 'cloud scout']),
    ('penguin',   ['linux', 'kernel', 'ubuntu', 'zorin', 'mint', 'debian', 'almalinux', 'red hat', 'rhel', 'fedora', 'sudo', 'systemd',
                   'glibc', 'openssh', 'openssl', 'samba', 'postfix', 'proxmox', 'usn-', 'dsa-', 'dla-', 'apt ', 'dpkg']),
    ('snake',     ['python', 'pypi', 'pip ', 'flask', 'fastapi', 'django', 'tkinter', 'pyqt', 'node.js', 'npm', 'docker', 'kubernetes', 'git ', 'gitlab', 'jenkins',
                   'ollama', 'redis', 'postgresql', 'mysql', 'mariadb', 'mongodb', 'elasticsearch', 'container']),
    ('window',    ['windows', 'microsoft', 'exchange server', 'microsoft exchange', 'exchange online', 'owa', 'hyper-v', 'rdp', 'entra', 'azure', 'intune', 'sharepoint',
                   'sql server', 'defender', 'bitlocker', 'ntlm', 'kerberos', 'active directory', 'iis', 'outlook',
                   'microsoft office', 'microsoft teams', 'onedrive', 'microsoft edge', 'msrc', 'cve-20', 'powershell']),
    ('electric_plug', ['fritz', 'home assistant', 'home-assistant', 'hass', 'eufy', 'ezviz', 'tp-link', 'nest', 'espressif', 'esp32', 'synology',
                   'qnap', 'samsung', 'xiaomi', 'huawei', 'android', 'iphone', 'ios ', 'macos', 'chrome', 'firefox',
                   'searxng', 'smart home', 'iot', 'camera', 'router', 'this pc', 'anora', 'noxa']),
    ('globe_with_meridians', ['mikrotik', 'routeros', 'cisco', 'fortinet', 'fortigate', 'palo alto', 'pan-os',
                   'ubiquiti', 'unifi', 'pfsense', 'citrix', 'netscaler', 'ivanti', 'sonicwall', 'watchguard',
                   'sophos', 'check point', 'juniper', 'aruba', 'zyxel', 'netgear', 'draytek', 'wireguard',
                   'openvpn', 'vpn', 'firewall', 'haproxy', 'f5 ', 'big-ip']),
    ('earth_africa', ['php', 'apache', 'joomla', 'wordpress', 'nginx', 'tomcat', 'nextcloud', 'drupal', 'zimbra',
                   'keycloak', 'webshell', 'web shell', 'cms', 'plugin']),
]
_DOMAIN_RES = [(tag, re.compile(r'(?<![a-z])(?:' + '|'.join(re.escape(t) for t in terms) + r')', re.I))
               for tag, terms in _DOMAIN_ICONS]

def _domain_tag(title, message):
    """The ntfy tag for the area an alert is about; 'shield' when nothing fits. 'cve-20' only counts for Windows
    when nothing else matched (Microsoft items often carry just the CVE id)."""
    low_t, low_m = title.lower(), (message or '')[:3000].lower()
    if _DOMAIN_RES[0][1].search(low_t):
        return 'clipboard'
    home = bool(_HOME_RE and (_HOME_RE.search(low_t) or _HOME_RE.search(low_m)))
    best, score = 'shield', 0
    for tag, rx in _DOMAIN_RES[1:]:
        n = 3 * len(rx.findall(low_t)) + len(rx.findall(low_m))
        if tag == 'window':
            n -= 3 * low_t.count('cve-20') + low_m.count('cve-20')
            n += 1 if 'cve-20' in low_t and score == 0 else 0
        if n > score:
            best, score = tag, n
    return ('house,' + best) if home else best

def alert(title, message, severity='warning', actions=None):
    """Send one push. v3.1: a push that cannot go out (no internet, ntfy busy or rate-limiting) is NOT lost: it is
    kept in data/outbox.jsonl and sent, marked "delayed", as soon as ntfy answers again (flush_outbox)."""
    if _state.get('cloud'):                        # v3.2: the cloud copy
        if _state.get('quiet'):                    # home is alive: read and remember, push nothing
            print(f"[QUIET] {title}")
            return
        title = '☁ ' + title                       # so you see which side sent it
    priority = {'info': 'low', 'warning': 'default', 'critical': 'urgent'}[severity]
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    body = f"Scout Alert\nTime: {now}\n─────────────────\n{message}"
    tags = _domain_tag(title, message)
    if severity == 'critical' and tags.startswith('house,penguin'):          # v3.6: a Linux CVE on his PCs → fix tracker
        _open_cve_add(CVE_RE.findall(title + ' ' + message), title)
    params = {'title': title, 'priority': priority, 'tags': tags, **({'actions': actions} if actions else {})}
    try:
        _ntfy_push(params, body)
        print(f"[ALERT] {title}")
        time.sleep(2)
    except Exception as e:
        print(f"[ALERT FAILED] {e} — kept in the outbox, sent when ntfy answers again")
        try:
            with open(OUTBOX, 'a', encoding='utf-8') as f:
                f.write(json.dumps({'t': time.time(), 'params': params, 'body': body}) + '\n')
        except OSError as e2:
            print(f"[ALERT LOST] outbox not writable: {e2}")

def flush_outbox():
    """Send what failed before, oldest first, urgent ones first; stop at the first failure (still offline)."""
    try:
        with open(OUTBOX, encoding='utf-8') as f:
            waiting = [json.loads(l) for l in f if l.strip()]
    except (OSError, ValueError):
        return
    if not waiting:
        return
    order = {'urgent': 0, 'default': 1, 'low': 2}
    waiting.sort(key=lambda e: (order.get(e['params'].get('priority'), 3), e['t']))
    left, sent = [], 0
    for i, e in enumerate(waiting):
        if time.time() - e['t'] > 48 * 3600 and e['params'].get('priority') != 'urgent':
            continue                                   # a routine push older than two days: not worth it any more
        first = datetime.datetime.fromtimestamp(e['t']).strftime('%a %H:%M')
        try:
            _ntfy_push(e['params'], f"⏱ Delayed — first tried {first} (no internet or ntfy busy)\n{e['body']}")
            sent += 1
            time.sleep(2)
        except requests.HTTPError as ex:
            if ex.response is not None and 400 <= ex.response.status_code < 500:
                print(f"[outbox] dropped '{e['params'].get('title')}': ntfy {ex.response.status_code} {ex.response.text[:100]}")
                continue                               # v3.6: a push ntfy refuses is not going to work later either
            left = waiting[i:]
            break
        except Exception:
            left = waiting[i:]
            break
    tmp = OUTBOX + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        for e in left:
            f.write(json.dumps(e) + '\n')
    os.replace(tmp, OUTBOX)
    if sent or left:
        print(f"[outbox] {sent} delayed push(es) sent, {len(left)} still waiting")

def _term_re(terms):
    """One regex for all terms, bounded by letters (digits and punctuation may follow: php8.4). v2.6: not right
    after a dot either — "edit_dealer.php" is a file name, not PHP."""
    return re.compile(r'(?<![a-z.])(?:' + '|'.join(re.escape(t) for t in sorted(terms, key=len, reverse=True)) + r')(?![a-z])')

_TERMS_RE     = _term_re(_ALL_TERMS)
_UNIVERSAL_RE = _term_re(_UNIVERSAL)

# v2.3 "eyes and ears": two tiers. An item about one of his CRITICAL products ([products] critical in scout.conf)
# that also carries an attack word is sent at once as critical — from any source. Everything else a news or blog
# feed matched goes into ONE digest per cycle, low priority, instead of one notification per feed.
CRITICAL_KEYWORDS = [k.strip().lower() for k in cfg.get('products', 'critical', fallback='').split(',') if k.strip()]
_CRITICAL_TERMS = list(CRITICAL_KEYWORDS)
for _kw in CRITICAL_KEYWORDS:
    _CRITICAL_TERMS.extend(_ALIASES.get(_kw, []))
_CRITICAL_RE = _term_re(_CRITICAL_TERMS) if _CRITICAL_TERMS else None

# v3.6: the HOME list — alerts that touch it get a 🏠 in front of the title (he reads those first)
_HOME_DEFAULT = ('Zorin, Ubuntu, Linux kernel, Debian, Python, Node.js, Docker, Git, OpenSSH, OpenSSL, sudo, systemd, Samba, '
                 'WireGuard, PHP, Apache, Joomla, Nginx, FRITZ, Home Assistant, Synology, Eufy, EZVIZ, TP-Link, Google Nest, '
                 'Espressif, Android, Samsung, Chrome, Firefox, Ollama, SearXNG')
HOME_KEYWORDS = [k.strip().lower() for k in (cfg.get('products', 'home', fallback='') or _HOME_DEFAULT).split(',') if k.strip()]
_HOME_TERMS = list(HOME_KEYWORDS)
for _kw in HOME_KEYWORDS:
    _HOME_TERMS.extend(_ALIASES.get(_kw, []))
_HOME_RE = _term_re(_HOME_TERMS) if _HOME_TERMS else None
# v3.6: [report] only = … — the 6 h report keeps only the items that name one of these products (home gear, Windows,
# Microsoft …); the rest is counted in one footer line. Urgent pushes, briefs and the weekly letter are not filtered.
REPORT_ONLY = [k.strip().lower() for k in cfg.get('report', 'only', fallback='').split(',') if k.strip()]
_REPORT_TERMS = list(REPORT_ONLY)
for _kw in REPORT_ONLY:
    _REPORT_TERMS.extend(_ALIASES.get(_kw, []))
_REPORT_RE = _term_re(_REPORT_TERMS) if _REPORT_TERMS else None

ATTACK_WORDS = ['exploit', 'exploited', 'exploits', 'exploitation', 'zero-day', '0-day', 'zeroday', 'in the wild',
                'rce', 'remote code execution', 'unauthenticated', 'pre-auth', 'critical', 'cve-', 'patch now',
                'emergency', 'wormable', 'backdoor', 'ransomware', 'bypass', 'privilege escalation',
                'mass exploitation', 'under attack', 'actively', 'hijack', 'takeover']
_ATTACK_RE = re.compile(r'(?<![a-z])(?:' + '|'.join(re.escape(w) for w in ATTACK_WORDS) + r')(?![a-z])')

# v3.6: "Apache James/Axis2/OFBiz/Juneau…" is a Java project of the foundation, not the web server on his list.
_APACHE_OTHER_RE = re.compile(r'apache\s+(?!httpd\b|http\b|web\b|2\b|2\.\d|server\b)[a-z][\w.]*')

def _norm(low):
    return _APACHE_OTHER_RE.sub('asf-project', low)

def _critical_hits(low):
    return {m.group(0) for m in _CRITICAL_RE.finditer(_norm(low))} if _CRITICAL_RE else set()

def is_urgent(text):
    """Critical product + attack word in the same title: the "cancer early" rule."""
    t = _norm(text.lower())
    if _NOISE_RE.search(t):
        return False
    if not (_CRITICAL_RE and _CRITICAL_RE.search(t) and _ATTACK_RE.search(t)):
        return False
    return True

# Items matched by news/blog feeds this cycle, sent as one digest at the end (reset in run_once)
_cycle_digest: list = []

# ── v2.4: the briefing — essentials always, Claude on top when it can ─────────────────────────────────────────
_CVSS_RE    = re.compile(r'\bCVSS(?:\s*v?3(?:\.\d)?)?[:\s]*(?:score[:\s]*)?(\d{1,2}(?:\.\d)?)\b', re.I)
_VERSION_RE = re.compile(r'\b(?:versions?|before|prior to|through|up to|earlier than|fixed in|patched in|upgrade to|'
                         r'<=?)\s*v?(\d+(?:\.\d+){1,3})', re.I)
_PRODUCT_NAMES = [k.strip() for k in cfg['products']['keywords'].split(',') if k.strip()]   # original spelling
_PRODUCT_RES   = [(n, re.compile(r'(?<![a-z])' + re.escape(n.lower()) + r'(?![a-z])')) for n in _PRODUCT_NAMES]

def essentials(raw_text):
    """What every alert carries even with no AI at all: the CVE ids, the CVSS score, which of YOUR products the
    text names, the attack words in it, and the versions it mentions. Deterministic, from the text only."""
    t = raw_text or ''
    low = t.lower()
    parts = []
    cves = sorted({c.upper() for c in CVE_RE.findall(t)})
    if cves:
        parts.append(', '.join(cves[:4]) + (f' +{len(cves) - 4}' if len(cves) > 4 else ''))
    m = _CVSS_RE.search(t)
    if m:
        parts.append(f"CVSS {m.group(1)}")
    prods = [n for n, r in _PRODUCT_RES if r.search(_norm(low))]
    if prods:
        parts.append('your stack: ' + ', '.join(prods[:4]))
    attack = [w for w in ATTACK_WORDS if w != 'cve-' and re.search(r'(?<![a-z])' + re.escape(w) + r'(?![a-z])', low)]
    if attack:
        parts.append('signals: ' + ', '.join(attack[:4]))
    vers = []
    for v in _VERSION_RE.findall(t):
        if v not in vers:
            vers.append(v)
    if vers:
        parts.append('versions: ' + ', '.join(vers[:3]))
    return ' | '.join(parts)

_CRITICAL_NAMES = [k.strip() for k in cfg.get('products', 'critical', fallback='').split(',') if k.strip()]

# v2.5: the briefing has a fixed shape — a verdict for HIS gear, the facts, and one thing to do.
_AI_SYSTEM = (
    "You brief a systems engineer on his phone about one security item. The products he runs and cares about most: "
    f"{', '.join(_CRITICAL_NAMES) or 'not given'}. Use ONLY the text given; never invent versions, CVE ids or facts — "
    "write 'not stated' instead of guessing.\n"
    "Answer in exactly three lines, plain text, no markdown, no preamble:\n"
    "Line 1: one verdict — PATCH NOW, PATCH SOON, WATCH or FYI — then ' – ' and the reason in at most 12 words. "
    "PATCH NOW only when it hits one of his products AND it is exploited in the wild, has a public exploit, or is "
    "unauthenticated remote code execution. PATCH SOON: his product and serious, but no sign of exploitation yet. "
    "WATCH: not clearly his product, or the details are still thin. FYI: background only.\n"
    "Line 2: two to four short sentences: the product and affected versions; what an attacker can do and whether it "
    "needs a login or user action; exploited in the wild, public exploit, or neither; the fix or mitigation.\n"
    "Line 3: 'Do: ' and one concrete action for him (the version to update to, the setting to change, what to check, "
    "or 'nothing for now').")
_VERDICT_ICON = (('PATCH NOW', '🔴'), ('PATCH SOON', '🟠'), ('WATCH', '🟡'), ('FYI', '⚪'))

def _format_ai(text):
    """Claude's three lines, the verdict marked with a colour, indented to sit under an alert item."""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if lines:
        head = lines[0].upper()
        for word, icon in _VERDICT_ICON:
            if head.startswith(word):
                lines[0] = f"{icon} {lines[0]}"
                break
    return '\n  '.join(lines)

def _ai_down(reason, minutes):
    account = reason.startswith(('no credit', 'the API key'))        # v3.6: not a blip — retry once a day, say so once
    if account:
        minutes = 24 * 60
    _ai_state['down_until'] = time.time() + minutes * 60
    _ai_state['reason'] = reason
    if not _ai_state['told']:
        print(f"[AI] briefings off for {minutes} min: {reason} — alerts carry the essentials")
        _ai_state['told'] = True
    if account and not _state.get('cloud'):
        seen = _seen(); today = datetime.date.today().isoformat()
        if seen.get('_ai_told_day') != today:
            seen['_ai_told_day'] = today
            alert('Scout: Claude is off', f"{reason}. Alerts, the 6 h report and the morning/evening briefs keep coming "
                  "without the explanations (plain lists) until it works again — nothing is lost.", severity='info')

def ai_call(system, content, max_tokens=2000, effort='low', model=None, timeout=40.0):
    """One Claude call with every failure handled: returns the text, or None (no key, no SDK, no credit, refused,
    network). A failure switches the AI off for a while instead of failing on every following item."""
    model = model or ANTHROPIC_MODEL
    if not ANTHROPIC_KEY or time.time() < _ai_state['down_until']:
        return None
    try:
        import anthropic
    except ImportError:
        _ai_down("the 'anthropic' package is not installed (pip install --user anthropic)", 6 * 60)
        return None
    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_KEY, max_retries=1, timeout=timeout)
        # max_tokens covers thinking too: Opus 5.5 always thinks, and at 400 Haiku 5.5 spent it all on thinking and
        # returned no text (seen 25 Oct). Haiku may switch thinking off (allowed at effort high or below).
        kwargs = dict(model=model, max_tokens=max_tokens, system=system, output_config={'effort': effort},
                      messages=[{'role': 'user', 'content': content}])
        if model.startswith('claude-haiku-5') and effort in ('low', 'medium', 'high'):
            kwargs['thinking'] = {'type': 'disabled'}
        if model in ('claude-opus-5-5', 'claude-opus-5', 'claude-sonnet-5-5', 'claude-fable-5-1'):
            resp = client.beta.messages.create(betas=['server-side-fallback-2026-07-01'], fallbacks='default', **kwargs)
        else:
            resp = client.messages.create(**kwargs)
        if resp.stop_reason == 'refusal':
            cat = getattr(getattr(resp, 'stop_details', None), 'category', None)
            print(f"[AI] refused ({cat}) — the fallback text is used")
            return None
        text = '\n'.join(b.text for b in resp.content if b.type == 'text').strip()
        if not text:
            print(f"[AI] empty answer (stop: {resp.stop_reason}) — the fallback text is used")
        return text or None
    except anthropic.AuthenticationError:
        _ai_down('the API key was refused', 6 * 60)
    except anthropic.PermissionDeniedError:
        _ai_down('the API key has no permission for this model', 6 * 60)
    except anthropic.RateLimitError:
        _ai_down('rate limited', 10)
    except anthropic.BadRequestError as e:
        msg = str(getattr(e, 'message', e))
        _ai_down('no credit left on the account' if 'credit' in msg.lower() else f"bad request: {msg[:80]}", 6 * 60)
    except anthropic.APIStatusError as e:
        _ai_down(f"API error {e.status_code}", 10)
    except anthropic.APIConnectionError:
        _ai_down('no connection to the API', 10)
    except Exception as e:
        _ai_down(f"{type(e).__name__}: {str(e)[:60]}", 10)
    return None

def ai_briefing(raw_text, context='threat'):
    """Claude's verdict + 2–4 sentences + action for one item, within the per-cycle cap; None when it can't."""
    if _state.get('quiet') or _ai_state['used'] >= AI_MAX_PER_CYCLE:
        return None
    text = ai_call(_AI_SYSTEM, f"Source: {context}\n\n{(raw_text or '')[:3000]}", effort='medium')
    if text is not None:
        _ai_state['used'] += 1
    return text


# ── v3.6 (the question: "what do I adjust for Zorin OS?"): every Linux alert says what it means for THIS PC ──────────
# Zorin 18 = Ubuntu 24.04 (noble) with the HWE kernel. Ubuntu's tracker (ubuntu.com/security/cves/<id>.json) knows,
# per package and release, whether the CVE is fixed, pending, needed or does not apply. Cached 6 h per CVE.
_LINUXISH_RE = re.compile(r'(?i)linux|kernel|ubuntu|debian|zorin|mint|glibc|openssh|openssl|systemd|sudo|samba|'
                          r'postfix|apt\b|dpkg|snap\b|gnome|xorg|wayland|grub|bash\b|curl\b|git\b|python|php|apache|nginx|'
                          r'docker|libssl|libxml|zlib|libpng|ffmpeg|chromium|firefox|thunderbird|libreoffice|cups|bluez|wpa')

# ubuntu.com stalls 20+ s (then times out) when the client asks for gzip — it answers in 0.1 s uncompressed (3 Nov)
UBUNTU_HEADERS = {'User-Agent': 'Mozilla/5.0', 'Accept-Encoding': 'identity'}

def _this_pc():
    """Codename, pretty name and the kernel package of the PC Scout runs on (from /etc/os-release and uname)."""
    pc = _state.get('_this_pc')
    if pc is None:
        pc = {'name': 'this PC', 'codename': 'noble', 'kernel': platform.release(), 'kpkg': 'linux-hwe-7.0'}
        try:
            osr = dict(l.rstrip('\n').split('=', 1) for l in open('/etc/os-release') if '=' in l)
            pc['name'] = osr.get('PRETTY_NAME', 'Linux').strip('"')
            pc['codename'] = (osr.get('UBUNTU_CODENAME') or osr.get('VERSION_CODENAME') or 'noble').strip('"')
        except OSError:
            pass
        pc['kpkg'] = next(iter(_kernel_pkgs({'me': {'codename': pc['codename'], 'kernel': pc['kernel']}}, pc['codename'])))
        _state['_this_pc'] = pc
    return pc

def _installed_src(src_pkg):
    """v3.6: the installed version of a source package on this PC ('' = not installed, None = unknown/cloud),
    from one dpkg listing kept for the run. Ubuntu's tracker names source packages (openssl, nginx, sudo)."""
    if _state.get('cloud'):
        return None
    table = _state.get('_dpkg')
    if table is None:
        table = {}
        try:
            import subprocess
            out = subprocess.run(['dpkg-query', '-W', '-f=${source:Package}\t${Package}\t${Version}\t${Status}\n'],
                                 capture_output=True, text=True, timeout=20).stdout
            for row in out.splitlines():
                srcp, binp, ver, status = (row.split('\t') + ['', '', '', ''])[:4]
                if status.endswith(' installed'):
                    table.setdefault(srcp.split(' ')[0], ver)
                    table.setdefault(binp, ver)
        except Exception as e:
            print(f"[zorin] dpkg listing failed: {e}")
            table = None
        _state['_dpkg'] = table
    return None if table is None else table.get(src_pkg, '')

def _apt_kernel_candidate():
    """v3.6: the newest kernel apt can install on this PC right now (from the kernel metapackages), '' = unknown.
    Ubuntu's CVE tracker lags the archive: 12 Nov it still said 'pending' while 7.0.0-43 was installable."""
    if _state.get('cloud'):
        return ''
    hit = _state.get('_apt_kcand')
    if hit and time.time() - hit[0] < 1800:
        return hit[1]
    best = ''
    try:
        import subprocess
        out = subprocess.run(['apt-cache', 'policy', 'linux-image-generic-hwe-24.04', 'linux-image-generic-hwe-22.04',
                              'linux-image-generic', 'linux-image-oem-24.04'], capture_output=True, text=True, timeout=20).stdout
        for cand in re.findall(r'Candidate:\s*(\S+)', out):
            if cand != '(none)' and _kver(cand) > _kver(best):
                best = cand
    except Exception as e:
        print(f"[zorin] apt-cache policy failed: {e}")
    _state['_apt_kcand'] = (time.time(), best)
    return best

def _ver_ge(a, b):
    import subprocess
    try:
        return subprocess.run(['dpkg', '--compare-versions', a, 'ge', b], timeout=5).returncode == 0
    except Exception:
        return False

def _status_text(entries, priority, pc):
    """entries = [(package, status, version)] for this PC's release → one line, the kernel compared with uname."""
    fixes, waits, na = [], [], 0
    for name, status, ver in entries:
        if name.startswith('linux') and name != pc['kpkg']:
            continue                                            # other kernel flavours (aws, azure, nvidia …)
        status, ver = (status or '').lower(), (ver or '').strip()[:40]
        if status in ('dne', 'not-affected'):
            na += 1
        elif status == 'released':
            if name.startswith('linux') and _kver(ver):
                run = _kver(pc['kernel'])
                fixes.append(f"{name} FIXED in {ver} — you run {pc['kernel']}: "
                             + ('ALREADY ON IT ✓' if run >= _kver(ver) else 'UPDATE + REBOOT NOW'))
            else:
                inst = _installed_src(name)
                if inst is None or not ver:
                    fixes.append(f"{name} FIXED in {ver} → APT UPGRADE if yours is older" if ver else f"{name} FIXED")
                elif inst == '':
                    fixes.append(f"{name} FIXED in {ver} — NOT INSTALLED HERE ✓")
                elif _ver_ge(inst, ver):
                    fixes.append(f"{name} FIXED in {ver} — you have {inst}: ALREADY ON IT ✓")
                else:
                    fixes.append(f"{name} FIXED in {ver} — you have {inst}: UPDATE NOW (apt upgrade)")
        elif status == 'pending' and name.startswith('linux') and _kver(ver) and _kver(_apt_kernel_candidate()) >= _kver(ver):
            run = _kver(pc['kernel'])                           # the archive has it although the tracker still says pending
            fixes.append(f"{name} FIX {ver} IS OUT — you run {pc['kernel']}: "
                         + ('ALREADY ON IT ✓' if run >= _kver(ver) else 'UPDATE + REBOOT NOW (sudo apt upgrade)'))
        elif status in ('pending', 'needed', 'needs-triage', 'deferred'):
            w = (f"{name}: FIX {ver or ''} PREPARED, NOT PUBLISHED YET".replace('  ', ' ') if status == 'pending'
                 else f"{name}: NO FIX YET ({status})")
            inst = None if name.startswith('linux') else _installed_src(name)
            if inst == '':
                w += " — NOT INSTALLED HERE ✓"
            elif inst:
                w += f" — you have {inst}"
                if name == 'openssh' and _installed_src('openssh-server') == '':
                    w += " (client only, NO SSH SERVER HERE ✓)"
            waits.append(w)
        elif status == 'ignored':
            waits.append(f"{name} IGNORED by Ubuntu" + (f" ({ver})" if ver else ''))
    if fixes:
        text = '; '.join(fixes[:3])
    elif waits:
        text = '; '.join(waits[:3])
    elif na:
        text = 'NOT AFFECTED'
    else:
        text = f"NOTHING LISTED for {pc['codename']} — treat as AFFECTED until Ubuntu says otherwise"
    if priority:
        text += f" [Ubuntu priority {priority}]"
    return text

_LP_STATUS_RE = re.compile(r'(?m)^(\w+)_([\w.+-]+):\s*([\w-]+)(?:\s*\(([^)]*)\))?')

def launchpad_status(cve, pc):
    """v3.6: Ubuntu's CVE tracker git repo (the source the website is built from). It knows CVEs the website hangs
    on, answers in 3-4 s, and says 404 at once for a CVE Ubuntu has never seen. '' = not there."""
    for folder in ('active', 'retired'):
        r = requests.get(f"https://git.launchpad.net/ubuntu-cve-tracker/plain/{folder}/{cve}", headers=UBUNTU_HEADERS, timeout=15)
        if r.status_code == 404:
            continue
        r.raise_for_status()
        body = r.text
        prio = re.search(r'(?m)^Priority:\s*(\w+)', body)
        entries = [(pkg, st, ver) for rel, pkg, st, ver in _LP_STATUS_RE.findall(body) if rel == pc['codename']]
        return _status_text(entries, prio.group(1) if prio else '', pc)
    return ''

def ubuntu_status(cve):
    """One short line for a CVE on this PC's release: 'linux-hwe-7.0: NO FIX YET (needed)' /
    'openssh FIXED in 1:9.6p1-3ubuntu13.5 → APT UPGRADE' / 'NOT AFFECTED'. ubuntu.com's JSON first (0.2 s when it
    knows the CVE, hangs when it does not), then the Launchpad tracker file; never silent on a Linux CVE."""
    cve = cve.upper()
    cache = _seen().setdefault('_ubu_cache', {})
    hit = cache.get(cve)
    if hit and time.time() - hit['t'] < 6 * 3600:
        return hit['s']
    if _state.get('cloud') and len(cache) > 400:
        cache.clear()
    pc = _this_pc()
    text, ttl = '', 6 * 3600
    try:
        r = requests.get(f"https://ubuntu.com/security/cves/{cve}.json", headers=UBUNTU_HEADERS, timeout=8)
        if r.status_code != 404:
            r.raise_for_status()
            d = r.json()
            entries = [(p_.get('name', ''), st.get('status'), st.get('description'))
                       for p_ in d.get('packages', []) for st in p_.get('statuses', [])
                       if st.get('release_codename') == pc['codename']]
            text = _status_text(entries, d.get('priority'), pc)
    except Exception as e:
        print(f"[zorin] {cve}: ubuntu.com {str(e)[:60]} — asking Launchpad")
    if not text:
        try:
            text = launchpad_status(cve, pc)
            if not text:
                text, ttl = "not in Ubuntu's tracker yet — treat as AFFECTED until it says otherwise", 2 * 3600
        except Exception as e:
            print(f"[zorin] {cve}: launchpad {str(e)[:60]}")
            text, ttl = "Ubuntu's tracker gave no answer — treat as AFFECTED until it does", 2 * 3600
    cache[cve] = {'t': time.time() - (6 * 3600 - ttl), 's': text}
    return text

def zorin_line(raw_text):
    """'🖥 Zorin OS 18.1: CVE-… linux-hwe-7.0 needed — no fix yet' for a Linux-ish item with CVE ids (at most 2)."""
    t = raw_text or ''
    if not _LINUXISH_RE.search(t):
        return ''
    cves = sorted({c.upper() for c in CVE_RE.findall(t)})[:2]
    parts = []
    kernelish = bool(re.search(r'(?i)linux kernel|\bkernel\b', t))
    for c in cves:
        st = ubuntu_status(c)
        if st and "not in Ubuntu's tracker" in st and not kernelish:
            continue                    # v3.6: a WordPress plugin or a PS5 emulator is not an Ubuntu package: say nothing
        if st:
            parts.append(f"{c} {st}")
    return f"🖥 {_this_pc()['name'].upper()} ▶ " + ' | '.join(parts) if parts else ''

def enrich(raw_text, context='threat', use_ai=True):
    """What an alert item carries: the essentials first (always), then Claude's verdict + briefing + action when it
    is available, else the start of the original text — a lost key or an empty credit never makes an alert say less."""
    ess = essentials(raw_text)
    zl = zorin_line(raw_text)                                     # v3.6: what it means for this PC, from Ubuntu's tracker
    ai_in = f"{raw_text}\n\n[Status on his own PC from Ubuntu's security tracker: {zl[2:]}]" if zl else raw_text
    ai = ai_briefing(ai_in, context) if use_ai else None
    parts = [f"📌 {ess}"] if ess else []
    if zl:
        parts.append(zl)
    parts.append(_format_ai(ai) if ai else (raw_text or '').strip()[:220])
    return '\n  '.join(p for p in parts if p)

# v2.6: CVE factories for student/demo projects (hundreds a month, nobody runs them in production)
_NOISE_RE = re.compile(r'sourcecodester|itsourcecode|code-projects|projectworlds|campcodes|phpgurukul|kashipara|'
                       r'fabian ros|carmelo|online (?:\w+ )?(?:management|booking|examination|ordering) system', re.I)

def matches(text):
    t = _norm(text.lower())
    if _NOISE_RE.search(t):
        return False
    return bool(_TERMS_RE.search(t) or _UNIVERSAL_RE.search(t))

# ── v2.8 (S3): the journal — every item that was alerted or put in a digest, kept 8 days, for the morning brief
# and the weekly letter. One JSON line per item in data/journal.jsonl.
JOURNAL = os.path.join(os.path.dirname(SEEN_DB), 'journal.jsonl')

def journal_add(severity, title, lines):
    now = time.time()
    try:
        with open(JOURNAL, 'a', encoding='utf-8') as f:
            for line in lines:
                if line and not line.startswith('──'):
                    f.write(json.dumps({'t': now, 'sev': severity, 'title': title, 'text': line[:1200]}) + '\n')
    except OSError as e:
        print(f"[journal] not written: {e}")

def journal_read(hours):
    cutoff, out = time.time() - hours * 3600, []
    try:
        with open(JOURNAL, encoding='utf-8') as f:
            for raw in f:
                try:
                    e = json.loads(raw)
                except ValueError:
                    continue
                if e.get('t', 0) >= cutoff:
                    out.append(e)
    except OSError:
        pass
    return out

def journal_prune(days=8):
    keep = journal_read(days * 24)
    try:
        tmp = JOURNAL + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            for e in keep:
                f.write(json.dumps(e) + '\n')
        os.replace(tmp, JOURNAL)
    except OSError as e:
        print(f"[journal] prune failed: {e}")

# ── v2.9 (S4): quality, so a loud scout stays a trusted one ──────────────────────────────────────────────────
_URL_RE = re.compile(r'https?://\S+')

def _seen():
    s = _state.get('seen')
    if s is None:
        s = _state.setdefault('_mem', {})
    return s

def _prod_re(name):
    return _term_re([name.lower()] + _ALIASES.get(name.lower(), []))

def _active_mutes():
    """[(product, until, regex)] from `[mute] items` (Chrome:24h counts from the first time the scout saw that line)
    and from the "Mute … for a day" button."""
    seen, now, out = _seen(), time.time(), []
    cfg_first = seen.setdefault('_mute_cfg', {})
    for entry in [e.strip() for e in cfg.get('mute', 'items', fallback='').split(',') if e.strip()]:
        m = re.fullmatch(r'(.+?)\s*:\s*(\d+)\s*([hd])', entry, re.I)
        if not m:
            continue
        start = cfg_first.setdefault(entry, now)
        until = start + int(m.group(2)) * (3600 if m.group(3).lower() == 'h' else 86400)
        if until > now:
            out.append((m.group(1).strip(), until, _prod_re(m.group(1).strip())))
    for prod, until in list(seen.get('_mute_cmd', {}).items()):
        if until > now:
            out.append((prod, until, _prod_re(prod)))
        else:
            del seen['_mute_cmd'][prod]
    return out

_LINUX_PRODS = {'linux kernel', 'linux', 'kernel', 'ubuntu', 'debian', 'zorin', 'zorin os', 'linux mint', 'openssh', 'openssl',
                'sudo', 'systemd', 'samba', 'glibc', 'python', 'docker', 'nginx', 'apache', 'php', 'postgresql', 'git'}

_SOCIAL_SRC = {'infosec.exchange', 'Google News', 'Telegram', 'HackerNews'}

def _route(title, lines):
    """Mute and one-story-one-alert for a routine push; what is held back goes to the digest with the reason."""
    seen, now = _seen(), time.time()
    src = title.split(':')[0]
    pushed = seen.setdefault('_pushed_cves', {})
    for c in [c for c, v in pushed.items() if now - v[0] > 24 * 3600]:
        del pushed[c]
    plinks = seen.setdefault('_pushed_links', {})          # v3.2: links too (news without a CVE id)
    for l in [l for l, t in plinks.items() if now - t > 24 * 3600]:
        del plinks[l]
    pprod = seen.setdefault('_pushed_prods', {})         # v3.6: a story without a CVE id, same critical product within 24 h
    for k, v in list(pprod.items()):
        if not isinstance(v, list):
            pprod[k] = [v, False]                           # entries written before the strong flag existed
    for k in [k for k, v in pprod.items() if now - v[0] > 24 * 3600]:
        del pprod[k]
    mutes, keep = _active_mutes(), []
    muted_accts = {a.strip().lstrip('@').lower() for a in cfg.get('mute', 'accounts', fallback='').split(',') if a.strip()}
    this_year = datetime.date.today().year
    for line in lines:
        low = line.lower()
        who = re.match(r'\*\s*@([\w.-]+):', line)                      # v3.6: Mastodon/Telegram account on the mute list
        if who and who.group(1).lower() in muted_accts:
            _cycle_digest.append(f"[{src}] {line}\n  (account @{who.group(1)} is on the [mute] accounts list)")
            continue
        # v3.6: on the social/news sources a list word often sits in a post that is not about that product (ransomware
        # victims, newsletters, vague stories). Claude's own verdict decides there: 🔴/🟠 push, 🟡 WATCH / ⚪ FYI → report.
        # Not applied when Claude gave no verdict (down), or when the Zorin line shows this PC still open.
        if src in _SOCIAL_SRC:
            verdict = re.search(r'(?m)^\s*([🔴🟠🟡⚪])', line)
            pc_open = re.search(r'🖥[^\n]*(NO FIX YET|PREPARED, NOT PUBLISHED|UPDATE NOW|UPDATE \+ REBOOT|treat as AFFECTED)', line)
            pc_safe = re.search(r'🖥[^\n]*(NOT INSTALLED HERE|ALREADY ON IT|NOT AFFECTED|NO SSH SERVER HERE)', line)
            if verdict and verdict.group(1) in '🟡⚪' and not (pc_open and not pc_safe):
                _cycle_digest.append(f"[{src}] {line}\n  (Claude's verdict {verdict.group(1)}: to the report, not a push)")
                continue
            first = _norm(low.split('\n')[0])
            if not verdict and not _critical_hits(first) and not (_HOME_RE and _HOME_RE.search(first)):
                _cycle_digest.append(f"[{src}] {line}\n  (no verdict and no product of yours in the headline: to the report)")
                continue
        m = _URL_RE.search(line)
        link = m.group(0).rstrip(').,;') if m else ''
        if link and link in plinks and not CVE_RE.search(line):
            when = datetime.datetime.fromtimestamp(plinks[link]).strftime('%H:%M')
            _cycle_digest.append(f"[{src}] {line}\n  (same link already pushed {when})")
            continue
        hit = next((p for p, u, r in mutes if r.search(low)), None)
        if hit:
            until = datetime.datetime.fromtimestamp(next(u for p, u, r in mutes if p == hit)).strftime('%a %H:%M')
            _cycle_digest.append(f"[{src}] {line}\n  (muted: {hit} until {until})")
            continue
        cves = {c.upper() for c in CVE_RE.findall(line)}
        prods = _critical_hits(low)
        head = low.split('\n')[0]
        if src == 'PoC-in-GitHub' and not prods and not (_HOME_RE and _HOME_RE.search(head)):
            _cycle_digest.append(f"[{src}] {line}\n  (PoC for a product that is not on your lists)")     # v3.6
            continue
        strong = bool(_STRONG_RE.search(head[:400]))
        if cves and not strong and all(int(c[4:8]) < this_year - 1 for c in cves) and src != 'CISA KEV':
            _cycle_digest.append(f"[{src}] {line}\n  (old CVE from {min(int(c[4:8]) for c in cves)}, nothing new in it)")
            continue                                                                                 # v3.6
        new_cves = cves - set(pushed)
        if prods and not new_cves and all(p in pprod for p in prods) and not (strong and not all(pprod[p][1] for p in prods)):
            when = datetime.datetime.fromtimestamp(min(pprod[p][0] for p in prods)).strftime('%H:%M')
            _cycle_digest.append(f"[{src}] {line}\n  (same product already pushed {when}, no new CVE id)")
            continue                                                 # v3.6: a strong word gets one extra push, not fourteen
        if cves and _LINUXISH_RE.search(head) and not (prods - _LINUX_PRODS):
            sts = [(c, ubuntu_status(c)) for c in sorted(cves)[:2]]  # v3.6: a kernel CVE this PC already has the fix for
            if sts and all(('ALREADY ON IT' in st) or ('NOT AFFECTED' in st) or ('NOT INSTALLED HERE' in st) for c, st in sts):
                z = ' | '.join(f"{c} {st}" for c, st in sts)
                _cycle_digest.append(f"[{src}] {line}\n  🖥 {_this_pc()['name'].upper()} ▶ {z}\n  (your PC is not exposed: to the report, not a push)")
                for c in cves:
                    pushed.setdefault(c, [now, src])
                continue
        if cves and all(c in pushed for c in cves):
            first = min((pushed[c] for c in cves), key=lambda v: v[0])
            when = datetime.datetime.fromtimestamp(first[0]).strftime('%H:%M')
            _cycle_digest.append(f"[{src}] {line}\n  (same story already pushed {when} via {first[1]})")
            continue
        for c in cves:
            pushed.setdefault(c, [now, src])
        if link:
            plinks.setdefault(link, now)
        for p_ in prods:
            pprod[p_] = [now, strong or (p_ in pprod and pprod[p_][1])]
        keep.append(line)
    held = len(lines) - len(keep)
    if held:
        print(f"[route] {title[:50]}: {held} of {len(lines)} item(s) to the digest (muted or already pushed)")
    return keep

def _ctl_topic():
    seen = _seen()
    t = cfg.get('ntfy', 'control_topic', fallback='').strip()
    if not t:
        if '_ctl_topic' not in seen:
            import secrets
            seen['_ctl_topic'] = f"{NTFY_TOPIC}-ctl-{secrets.token_hex(6)}"
        t = seen['_ctl_topic']
    return t

def _actions(title, page):
    """ntfy buttons: Open (the first link), Mute <product> for a day, Useful. The two taps publish a short command
    to the scout's own secret control topic, which it reads every fast check — no port is opened at home."""
    ctl = f"{NTFY_SERVER}/{_ctl_topic()}"
    src = re.sub(r'[^A-Za-z0-9 ._-]', '', title.split(':')[0])[:40] or 'Scout'
    acts = []
    url = _URL_RE.search(page)
    if url:
        link = url.group(0).rstrip(').,;').replace(',', '%2C').replace(';', '%3B')   # v3.6: a comma in the link = a new
        acts.append(f"view, Open, {link}")                                           # field for ntfy → 400, push stuck
    low = page.lower()
    prod = next((n for n in _CRITICAL_NAMES if _prod_re(n).search(low)), None) or \
           next((n for n in _PRODUCT_NAMES if _prod_re(n).search(low)), None)
    if prod:
        acts.append(f"http, Mute {prod} 1 day, {ctl}, method=POST, body=mute {prod} 24h, clear=true")
    acts.append(f"http, 👍 Useful, {ctl}, method=POST, body=useful {src}")
    return '; '.join(acts[:3])

def _count_push(title):
    log = _seen().setdefault('_push_log', [])
    log.append([time.time(), title.split(':')[0][:40]])
    cutoff = time.time() - 8 * 86400
    while log and log[0][0] < cutoff:
        log.pop(0)

def poll_control(seen):
    """The taps on the buttons: 'mute <product> <N>h|d', 'unmute <product>|all', 'useful <source>'. Only names from
    the product list can be muted, for at most 30 days; anything else is ignored."""
    try:
        since = seen.get('_ctl_since', '12h')
        r = requests.get(f"{NTFY_SERVER}/{_ctl_topic()}/json", params={'poll': '1', 'since': since}, timeout=15)
        r.raise_for_status()
    except Exception as e:
        print(f"[control] not read: {e}")
        return
    names = {n.lower(): n for n in _PRODUCT_NAMES}
    for raw in r.text.splitlines():
        try:
            ev = json.loads(raw)
        except ValueError:
            continue
        if ev.get('event') != 'message':
            continue
        seen['_ctl_since'] = ev.get('id', since)
        cmd = ' '.join((ev.get('message') or '').split())[:80]
        m = re.fullmatch(r'(?i)mute (.+?) (\d{1,3}) ?([hd])', cmd)
        if m and m.group(1).lower() in names:
            prod = names[m.group(1).lower()]
            secs = min(30 * 86400, int(m.group(2)) * (3600 if m.group(3).lower() == 'h' else 86400))
            seen.setdefault('_mute_cmd', {})[prod] = time.time() + secs
            until = datetime.datetime.fromtimestamp(time.time() + secs).strftime('%a %d %b %H:%M')
            alert(f"Scout: {prod} muted until {until}",
                  f"Pushes about {prod} go to the digest until {until}.\nUndo: publish 'unmute {prod}' to the "
                  f"control topic, or remove it from [mute] items.", severity='info')
            continue
        m = re.fullmatch(r'(?i)unmute (.+)', cmd)
        if m:
            mc = seen.setdefault('_mute_cmd', {})
            gone = list(mc) if m.group(1).lower() == 'all' else [p for p in mc if p.lower() == m.group(1).lower()]
            for p in gone:
                del mc[p]
            if gone:
                alert("Scout: unmuted", ', '.join(gone), severity='info')
            continue
        m = re.fullmatch(r'(?i)useful (.{1,40})', cmd)
        if m:
            log = seen.setdefault('_useful_log', [])
            log.append([time.time(), m.group(1)])
            seen['_useful_log'] = [x for x in log if time.time() - x[0] < 8 * 86400]
            continue
        print(f"[control] ignored: {cmd!r}")

def push_stats(days=7):
    """The weekly 'which sources earn their pushes' line."""
    seen, cutoff = _seen(), time.time() - days * 86400
    pushes, useful = {}, {}
    for t, src in seen.get('_push_log', []):
        if t >= cutoff:
            pushes[src] = pushes.get(src, 0) + 1
    for t, src in seen.get('_useful_log', []):
        if t >= cutoff:
            useful[src] = useful.get(src, 0) + 1
    if not pushes:
        return []
    top = sorted(pushes.items(), key=lambda x: -x[1])[:6]
    return [f"PUSHES: {sum(pushes.values())} this week, {sum(useful.values())} marked 👍 useful.",
            "Most pushes: " + ', '.join(f"{s} {n}" + (f" ({useful.get(s, 0)}👍)" if useful.get(s) else '') for s, n in top)]

# ── v3.0 (S5, standalone): the scout watches itself ──────────────────────────────────────────────────────────
HEARTBEAT = os.path.join(os.path.dirname(SEEN_DB), 'heartbeat.json')
VERSION = '3.6'
_progress = {'ts': time.time()}

def heartbeat(stage, **extra):
    """Written after every lane (and while offline): what scout_watch.py and the next start read. Atomic write."""
    _progress['ts'] = time.time()
    data = {'ts': time.time(), 'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'stage': stage,
            'version': VERSION, 'pid': os.getpid(), 'fast_minutes': FAST_MINUTES,
            'ok': _last_health.get('ok'), 'total': _last_health.get('total'), 'errors': len(_cycle_errors), **extra}
    try:
        tmp = HEARTBEAT + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(data, f)
        os.replace(tmp, HEARTBEAT)
    except OSError as e:
        print(f"[heartbeat] not written: {e}")

def hb_topic():
    """The private topic the home Scout says "alive" on (the phone does not subscribe to it); the cloud watch reads it."""
    return cfg.get('ntfy', 'heartbeat_topic', fallback='').strip() or f"{_ctl_topic()}-hb"

def cloud_heartbeat():
    """v3.1: tell the cloud watch (GitHub Actions) that the home Scout is alive, so it stays silent."""
    try:
        requests.post(f"{NTFY_SERVER}/{hb_topic()}", data=f"alive {VERSION} {datetime.datetime.now():%H:%M}".encode(),
                      params={'priority': 'min'}, timeout=10)
    except Exception as e:
        print(f"[cloud-heartbeat] not sent: {e}")

def _read_heartbeat():
    try:
        with open(HEARTBEAT) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None

def start_report(seen):
    """At start: was the scout away, and why — a clean stop (restart, shutdown) or gone without a word (crash,
    power cut)? A gap over 45 min is told in one low-priority line; restarts of the last 7 days are counted."""
    hb = _read_heartbeat()
    now = time.time()
    starts = [t for t in seen.get('_starts', []) if now - t < 7 * 86400] + [now]
    seen['_starts'] = starts
    if not hb:
        return
    gap = now - float(hb.get('ts', now))
    how = ("stopped cleanly (restart or shutdown)" if hb.get('stage') == 'stopped'
           else "gone without a word (crash, hang or power cut)")
    print(f"[Scout] last heartbeat {hb.get('time')} ({gap / 60:.0f} min ago), {how}")
    if gap > 45 * 60:
        alert("Scout: back after a gap",
              f"Not running from {hb.get('time', '?')[:16]} to {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} "
              f"({gap / 3600:.1f} h) — {how}.\nThe first checks now read what was missed; feeds only keep their latest "
              f"items, so a long gap can hide older ones (the morning brief covers the rest).\n"
              f"Starts in the last 7 days: {len(starts)}.", severity='info')

def _on_stop(signum, frame):
    """systemctl stop / restart / shutdown: say so in the heartbeat, so the next start knows it was not a crash."""
    try:
        save_seen(_seen())
    except Exception:
        pass
    heartbeat('stopped')
    raise SystemExit(0)

def _watchdog():
    """A thread that ends the process when the main loop stops moving (a hung connection, a stuck parser): no
    progress for a whole fast interval + 45 min → exit 3, and systemd (Restart=on-failure) starts it again."""
    limit = FAST_MINUTES * 60 + 45 * 60
    while True:
        time.sleep(60)
        idle = time.time() - _progress['ts']
        if idle > limit:
            print(f"[watchdog] no progress for {idle / 60:.0f} min — exiting so systemd restarts the scout", flush=True)
            try:
                heartbeat('hung')
            finally:
                os._exit(3)

def online():
    """Is there internet at all? During an outage every source waited 20 s for DNS (558 s for one fast lane, 25 Oct)
    and would have counted a failure each time."""
    import socket
    for host in ('ntfy.sh', 'www.cisa.gov', 'github.com'):
        try:
            socket.getaddrinfo(host, 443)
            return True
        except OSError:
            continue
    return False

def alert_all(title, lines, severity='warning', limit=3500, journal=True, routine=True):
    """v2.3, design rule: "better more info than less" — every line is sent, in pages that fit one ntfy message
    (4 KB); page 2+ carries the same title with (2/3). v2.8: every item also goes into the journal.
    v2.9: a routine push first drops the items about a muted product and the items whose CVEs were already pushed
    in the last 24 h — both go to the digest with a note, never away. Not routine (always pushed): Confirmed, KEV,
    Microsoft exploited, Patch Tuesday, MikroTik, this PC, the briefs and the digest."""
    if routine:
        lines = _route(title, lines)
        if not lines:
            return
        n = len(lines)
        title = re.sub(r'\b\d+(?= (?:urgent|item|CVE|new|exploit|vuln|relevant|with))', str(n), title, count=1)
    if journal:
        journal_add(severity, title, lines)
    if not _state.get('quiet'):
        _count_push(title)
    pages, cur = [], ''
    for line in lines:
        if cur and len((cur + '\n' + line).encode('utf-8')) > limit:
            pages.append(cur); cur = line
        else:
            cur = line if not cur else cur + '\n' + line
    if cur:
        pages.append(cur)
    for i, page in enumerate(pages, 1):
        alert(title if len(pages) == 1 else f"{title} ({i}/{len(pages)})", page, severity=severity,
              actions=_actions(title, page) if journal else None)

_cycle_cve_prods: dict = {}                         # v3.6: CVE → the products of his lists named next to it

def track_cves(text, source):
    """Extract CVE IDs from text and record which source mentioned them this cycle, and which of his products
    the text names (for the Trending push: only CVEs about his gear are worth a push)."""
    cves = {c.upper() for c in CVE_RE.findall(text)}
    if not cves:
        return
    low = _norm(text.lower())
    prods = [n for n, r in _PRODUCT_RES if r.search(low)]
    for cve_id in cves:
        _cycle_cve_hits.setdefault(cve_id, [])
        if source not in _cycle_cve_hits[cve_id]:
            _cycle_cve_hits[cve_id].append(source)
        for p_ in prods:
            if p_ not in _cycle_cve_prods.setdefault(cve_id, []):
                _cycle_cve_prods[cve_id].append(p_)

# ── v2.5: "confirmed within the hour" ─────────────────────────────────────────────────────────────────────────
# A CVE named by two independent sources (news, lists, vendors, Mastodon, HN, PoC repos, KEV — not the CVE databases)
# within 60 minutes, about your stack or in KEV, is sent at once as critical with every link. Only NEW items count:
# _mentions_seen remembers what was already read, and the first pass after a start only primes it (no alert).
CONFIRM_WINDOW = 3600
_mentions_seen: dict = {}    # "source|link" -> time first read
_cve_window: dict = {}       # CVE -> {source: (time, title, link)}
_state = {'primed': False, 'seen': None}
_src_first: dict = {}        # source -> when mention() first heard from it in this run

def mention(text, source, link='', title=''):
    cves = {c.upper() for c in CVE_RE.findall(text or '')}
    if not cves:
        return
    key = f"{source}|{link or (title or text)[:100]}"
    if key in _mentions_seen:
        return
    now = time.time()
    _mentions_seen[key] = now
    # v2.9: the first read of a source in this run (at start, or when it comes back after an outage) is old news:
    # remember it, don't let it "confirm" anything. Seen 25 Oct 22:42: 5 false "Confirmed" after a 20-min outage.
    if not _state.get('cloud') and now - _src_first.setdefault(source, now) < 120:
        return                                     # (the cloud keeps its window between runs instead)
    for cve in cves:
        srcs = {s: v for s, v in _cve_window.get(cve, {}).items() if now - v[0] <= CONFIRM_WINDOW}
        srcs.setdefault(source, (now, ' '.join((title or text).split())[:160], link))
        _cve_window[cve] = srcs
        seen = _state['seen']
        if not _state['primed'] or seen is None or len(srcs) < 2 or f"confirmed_{cve}" in seen:
            continue
        texts = ' '.join(v[1] for v in srcs.values())
        if matches(texts) or 'CISA-KEV' in srcs:
            seen[f"confirmed_{cve}"] = True
            _send_confirmed(cve, srcs)

def _send_confirmed(cve, srcs):
    times = [v[0] for v in srcs.values()]
    span = max(1, round((max(times) - min(times)) / 60))
    texts = '. '.join(v[1] for v in srcs.values())
    seen = _state['seen']
    for other in {c.upper() for c in CVE_RE.findall(texts)}:      # one story with two CVEs = one alert
        seen[f"confirmed_{other}"] = True
    lines = [enrich(f"{cve}. {texts}", f"{cve} confirmed by {len(srcs)} sources")]
    for s, (_, t, l) in sorted(srcs.items(), key=lambda x: x[1][0]):
        lines.append(f"• {s}: {t}" + (f"\n  {l}" if l else ''))
    alert_all(f"Confirmed: {cve} — {len(srcs)} sources within {span} min", lines, severity='critical', routine=False)

def _prune_mentions():
    now = time.time()
    for k in [k for k, t in _mentions_seen.items() if now - t > 3 * 86400]:
        del _mentions_seen[k]
    for cve in list(_cve_window):
        srcs = {s: v for s, v in _cve_window[cve].items() if now - v[0] <= CONFIRM_WINDOW}
        if srcs:
            _cve_window[cve] = srcs
        else:
            del _cve_window[cve]

# Hacker News and Mastodon talk about Python, Git, Chrome… all day; only stories with a security word count there.
_SEC_HINT_RE = re.compile(
    r'(?<![a-z])(?:vulnerab\w*|exploit\w*|cve-\d|zero-?day|0-?day|rce|remote code|breach\w*|hack(?:ed|ers?)|'
    r'backdoor\w*|malware|ransomware|compromis\w*|attack\w*|patch(?:es|ed)?|security|flaw\w*|leak\w*|phishing|'
    r'botnet|worm|privilege escalation|bypass\w*|injection|takeover|hijack\w*)')

def is_security_story(text):
    t = (text or '').lower()
    if _NOISE_RE.search(t):
        return False
    return bool(_UNIVERSAL_RE.search(t) or (_TERMS_RE.search(t) and _SEC_HINT_RE.search(t)))

def source_error(name, e):
    """Record a source failure; escalate to a critical alert after 3 failures in a row (9 for a fast-lane source,
    which is read every FAST_MINUTES, so a short network drop doesn't wake you)."""
    msg = f"{type(e).__name__}: {str(e)[:120]}"
    print(f"[{name}] error: {e}")
    entry = _cycle_errors.setdefault(name, [0, msg])
    entry[0] += 1
    entry[1] = msg
    _fail_counts[name] = _fail_counts.get(name, 0) + 1
    # v3.3: a site that refuses us (403) or whose address is gone (404) three times in a row is PARKED for 24 h and
    # retried daily — one info line the first time, never a "failing repeatedly" alarm (CISA blocked every reader on
    # 26 Oct; from the cloud any 3 failures park, GitHub's addresses are refused by a dozen sites).
    persistent = msg.startswith('ConnectionError: HTTP 40')
    if (_state.get('cloud') or persistent) and _fail_counts[name] >= 3:
        seen = _seen()
        seen.setdefault('_parked', {})[name] = time.time() + 24 * 3600
        _fail_counts[name] = 0
        told = seen.setdefault('_parked_told', {})
        print(f"[{name}] parked for 24 h: {msg[:80]}")
        if name not in told and not _state.get('cloud'):
            told[name] = datetime.date.today().isoformat()
            alert(f"Scout: {name} parked", f"{name} refuses the scout or moved: {msg[:140]}.\nIt is retried once a "
                  f"day and comes back by itself when it works again. No further alarms about it.", severity='info')
        return
    limit = 9 if (name in FAST_RSS or name in FAST_CHECK_NAMES) else 3
    if _fail_counts[name] == limit:
        alert(
            f"Scout: {name} failing repeatedly",
            f"{name} has failed {limit} checks in a row.\nLast error: {str(e)[:200]}",
            severity='critical'
        )

_cycle_recovered: dict = {}   # name -> how many brief errors it had and then worked again (reset per slow lane)

def source_ok(name):
    """Clear the failure counter when a source succeeds. v3.5: a source that failed earlier in the window and works
    now is a recovered blip, not a failure — it leaves the failed list (Exploit-DB's 502s were listed 34 times)."""
    if _fail_counts.get(name, 0) > 0:
        _fail_counts[name] = 0
    entry = _cycle_errors.pop(name, None)
    if entry:
        _cycle_recovered[name] = _cycle_recovered.get(name, 0) + entry[0]
    told = _seen().get('_parked_told', {})
    if name in told:                                   # it works again: say so once, and alarm again if it breaks
        del told[name]
        print(f"[{name}] works again after being parked")

def maybe_summarize(raw_text, context='threat'):
    """Kept for the callers: the v2.4 briefing (essentials always, Claude on top when it can)."""
    return enrich(raw_text, context)

def get_with_retry(url, headers=None, timeout=15, retries=3, backoff=4, **kwargs):
    """GET with exponential backoff on 429 / connection errors."""
    h = headers or HEADERS
    kwargs = dict(kwargs)
    for attempt in range(retries + 1):                        # +1: room for the single 5xx retry
        if attempt == retries and not kwargs.get('_retried_5xx'):
            break
        try:
            r = requests.get(url, headers=h, timeout=timeout, **{k: v for k, v in kwargs.items() if k != '_retried_5xx'})
            if r.status_code in (502, 503, 504) and not kwargs.get('_retried_5xx'):   # v3.5: one quick retry
                time.sleep(3)
                kwargs['_retried_5xx'] = True
                continue
            if r.status_code == 429:
                if attempt == retries - 1:
                    return r                                   # the caller sees the 429 (fast lane: demote)
                wait = backoff * (2 ** attempt)
                print(f"  [rate-limit] {url[:60]} — waiting {wait}s")
                time.sleep(wait)
                continue
            return r
        except requests.RequestException as e:
            if attempt < retries - 1:
                wait = backoff * (2 ** attempt)
                print(f"  [error] {e} — retrying in {wait}s")
                time.sleep(wait)
            else:
                raise
    return None

def cond_get(url, headers=None, timeout=15, retries=3):
    """GET that sends the feed's last ETag / Last-Modified: an unchanged feed answers 304 with no body, which is
    what makes reading KEV (1.7 MB) and MSRC (2.8 MB) every 20 minutes cheap."""
    h = dict(headers or HEADERS)
    etag, lastmod = _validators.get(url, (None, None))
    if etag:
        h['If-None-Match'] = etag
    if lastmod:
        h['If-Modified-Since'] = lastmod
    r = get_with_retry(url, headers=h, timeout=timeout, retries=retries)
    if r is not None and r.status_code == 200:
        _validators[url] = (r.headers.get('ETag'), r.headers.get('Last-Modified'))
    return r

class GitHubLimit(Exception):
    """GitHub refused the call (rate limit spent, or a bad token): a source failure, never "nothing new"."""

_gh_token_dead = False

def gh_get(url, name, timeout=15):
    """GET from the GitHub API with the token if there is one; 403/429 raise GitHubLimit, so the calling check lands
    in source_error() and the failure digest instead of looking quiet. v3.3: a token GitHub rejects (401 — revoked
    or expired) is dropped for the rest of the run and the call is made without it (60 calls/h, the scout needs
    ~14): one info push, never seven failing checks."""
    global _gh_token_dead
    headers = GH_HEADERS if not _gh_token_dead else {k: v for k, v in GH_HEADERS.items() if k != 'Authorization'}
    r = requests.get(url, headers=headers, timeout=timeout)
    if r.status_code == 401 and 'Authorization' in headers:
        _gh_token_dead = True
        print("[GitHub] the token was rejected (revoked or expired) — continuing without it")
        if not _state.get('cloud'):
            alert("Scout: GitHub token rejected", "GitHub answers 401 for the token in scout.conf [github]. The scout "
                  "continues without it (60 calls an hour, enough). For 5 000/h make a new classic token with NO "
                  "scopes and paste it there.", severity='info')
        return gh_get(url, name, timeout)
    if r.status_code in (401, 403, 429):
        try:
            msg = str(r.json().get('message', ''))[:90]
        except ValueError:
            msg = r.text[:90]
        hint = '' if GITHUB_TOKEN else ' — add a token in scout.conf [github]'
        raise GitHubLimit(f"HTTP {r.status_code} {msg}{hint}")
    return r

def parse_xml_robust(content):
    """Parse XML; fall back to lxml recover=True for broken feeds."""
    try:
        return ET.fromstring(content)
    except ET.ParseError:
        try:
            from lxml import etree
            parser = etree.XMLParser(recover=True, encoding='utf-8')
            lxml_root = etree.fromstring(content, parser)
            clean = etree.tostring(lxml_root, encoding='unicode')
            return ET.fromstring(clean)
        except Exception as e2:
            print(f"  [xml-fallback] lxml also failed: {e2}")
            return None

def enrich_epss(cve_ids):
    """Fetch EPSS exploitation-probability scores from FIRST.org for a list of CVE IDs.
    Returns dict {cve_id: epss_float}. Silently returns {} on any error."""
    if not cve_ids:
        return {}
    try:
        params = ','.join(cve_ids[:30])
        r = requests.get(
            f"https://api.first.org/data/v1/epss?cve={params}",
            headers=HEADERS, timeout=10
        )
        if r.status_code != 200:
            return {}
        return {d['cve']: float(d['epss']) for d in r.json().get('data', [])}
    except Exception:
        return {}

# ── source checkers ───────────────────────────────────────────────────────────

def check_cisa_kev(seen):
    print("[CISA KEV] checking...")
    try:
        r = cond_get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
                     HEADERS, timeout=30)
        if r.status_code == 304:
            print("[CISA KEV] unchanged")
            source_ok('CISA-KEV')
            return
        r.raise_for_status()
        cutoff      = datetime.date.today() - datetime.timedelta(days=LOOKBACK)
        new_items   = []
        new_any     = []
        for vuln in r.json().get('vulnerabilities', []):
            cve_id    = vuln.get('cveID', '')
            added_str = vuln.get('dateAdded', '1970-01-01')
            try:
                added = datetime.date.fromisoformat(added_str)
            except Exception:
                continue
            if added < cutoff:
                continue
            name    = vuln.get('vulnerabilityName', '')
            desc    = vuln.get('shortDescription', '')
            vendor  = vuln.get('vendorProject', '')
            product = vuln.get('product', '')
            due     = vuln.get('dueDate', '')
            track_cves(cve_id, 'CISA-KEV')
            # Stack-specific alert
            if cve_id not in seen and matches(f"{name} {desc} {vendor} {product}"):
                seen[cve_id] = True
                raw = f"{cve_id} - {name} ({vendor} {product}) patch by {due}. {desc}"
                new_items.append(f"* {maybe_summarize(raw, 'KEV exploit')}")
            # Situational awareness — any new KEV entry regardless of product
            key_any = f"kev_any_{cve_id}"
            if added >= (datetime.date.today() - datetime.timedelta(days=2)):
                mention(cve_id, 'CISA-KEV', f"https://nvd.nist.gov/vuln/detail/{cve_id}", f"{vendor} {product}: {name}")
            if key_any not in seen and added >= (datetime.date.today() - datetime.timedelta(days=2)):
                seen[key_any] = True
                new_any.append(f"* {cve_id} — {vendor} {product}: {name[:80]}")
        if new_items:
            alert_all(f"CISA KEV: {len(new_items)} new (your stack)", new_items, severity='critical', routine=False)
        if new_any:
            alert_all(f"CISA KEV (any): {len(new_any)} new exploited CVE(s)", new_any, severity='info', routine=False)
        if not new_items and not new_any:
            print("[CISA KEV] nothing new")
        source_ok('CISA-KEV')
    except Exception as e:
        source_error('CISA-KEV', e)

def _nvd_query(seen, start_param, end_param, label):
    """Shared NVD query logic for both published and modified CVE checks."""
    now   = datetime.datetime.now(datetime.timezone.utc)
    since = (now - datetime.timedelta(days=2)).strftime('%Y-%m-%dT00:00:00.000')
    until = now.strftime('%Y-%m-%dT23:59:59.999')
    url   = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?{start_param}={since}&{end_param}={until}&cvssV3Severity=CRITICAL"
    )
    r    = requests.get(url, headers=HEADERS, timeout=20)
    data = r.json()
    candidates = []
    for item in data.get('vulnerabilities', []):
        cve    = item.get('cve', {})
        cve_id = cve.get('id', '')
        descs  = cve.get('descriptions', [])
        desc   = next((d['value'] for d in descs if d['lang'] == 'en'), '')
        score  = 0
        try:
            score = item['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
        except Exception:
            pass
        key = f"nvd_{label}_{cve_id}"
        if key not in seen and score >= MIN_CVSS and matches(desc):
            candidates.append((key, cve_id, score, desc))
    if not candidates:
        print(f"[NVD {label}] nothing new")
        return
    epss = enrich_epss([c[1] for c in candidates])
    new_items = []
    for key, cve_id, score, desc in candidates:
        seen[key] = True
        ep     = epss.get(cve_id)
        ep_str = f" EPSS:{ep:.0%}" if ep is not None else ""
        # v2.5: Claude only for your critical gear or a real exploitation chance; the rest gets the essentials.
        # (Before, every briefing was cut to 110 characters here — paid for, then thrown away.)
        use_ai = bool(_CRITICAL_RE and _CRITICAL_RE.search(desc.lower())) or (ep or 0) >= 0.1
        summary = enrich(desc, f"CVE {cve_id} CVSS:{score}{ep_str}", use_ai=use_ai)
        new_items.append(f"* {cve_id} CVSS:{score}{ep_str}\n  {summary[:900]}")
        track_cves(cve_id, f"NVD-{label}")
    sev = 'critical' if any(epss.get(c[1], 0) >= 0.5 for c in candidates) else 'warning'
    alert_all(f"NVD {label}: {len(new_items)} CVE(s)", new_items, severity=sev)

def check_nvd(seen):
    print("[NVD published] checking...")
    try:
        _nvd_query(seen, 'pubStartDate', 'pubEndDate', 'published')
        source_ok('NVD')
    except Exception as e:
        source_error('NVD', e)

def check_nvd_modified(seen):
    """Catch CVEs that were re-scored to CRITICAL after initial publication."""
    print("[NVD modified] checking...")
    try:
        _nvd_query(seen, 'lastModStartDate', 'lastModEndDate', 'modified')
        source_ok('NVD-modified')
    except Exception as e:
        source_error('NVD-modified', e)

def check_circl(seen):
    """CIRCL CVE API — OSV-format feed, last 30 entries. CVE ID lives in aliases[]."""
    print("[CIRCL CVE] checking...")
    try:
        r = requests.get('https://cve.circl.lu/api/last/30', headers=HEADERS, timeout=15)
        if r.status_code != 200:
            print(f"[CIRCL CVE] HTTP {r.status_code}")
            return
        try:
            payload = r.json()
        except ValueError:
            print(f"[CIRCL CVE] bad JSON: {r.text[:80]}")
            return
        new_items = []
        for entry in (payload if isinstance(payload, list) else []):
            # OSV format: CVE ID is inside aliases[], description is in 'details'
            cve_id  = next((a for a in entry.get('aliases', []) if a.upper().startswith('CVE-')), entry.get('id', ''))
            summary = entry.get('details', '') or entry.get('summary', '') or entry.get('description', '')
            key     = f"circl_{cve_id}"
            if key not in seen and matches(summary):
                seen[key] = True
                track_cves(cve_id, 'CIRCL')
                new_items.append(f"* {cve_id}: {summary[:110]}")
        if new_items:
            alert_all(f"CIRCL CVE: {len(new_items)} matching CVE(s)", new_items, severity='warning')
        else:
            print("[CIRCL CVE] nothing new")
        source_ok('CIRCL')
    except Exception as e:
        source_error('CIRCL', e)

def check_osv(seen):
    print("[OSV.dev] checking...")
    try:
        cutoff = (datetime.date.today() - datetime.timedelta(days=LOOKBACK)).isoformat()
        new_items = []
        for eco in ['PyPI', 'npm', 'PHP', 'Go', 'Maven', 'NuGet', 'Linux']:
            body = json.dumps({"package": {"ecosystem": eco}})
            r    = requests.post(
                "https://api.osv.dev/v1/query",
                data=body,
                headers={**HEADERS, 'Content-Type': 'application/json'},
                timeout=15
            )
            if r.status_code != 200:
                continue
            for vuln in r.json().get('vulns', [])[:10]:
                osv_id   = vuln.get('id', '')
                summary  = vuln.get('summary', '') or vuln.get('details', '')[:100]
                modified = vuln.get('modified', '1970-01-01')[:10]
                key      = f"osv_{osv_id}"
                if key not in seen and modified >= cutoff and matches(summary):
                    seen[key] = True
                    new_items.append(f"* [{eco}] {osv_id}: {summary[:100]}\n  https://osv.dev/vulnerability/{osv_id}")
        if new_items:
            alert_all(f"OSV.dev: {len(new_items)} vuln(s)", new_items, severity='warning')
        else:
            print("[OSV.dev] nothing new")
        source_ok('OSV')
    except Exception as e:
        source_error('OSV', e)

def check_github_advisories(seen):
    print("[GitHub Advisories] checking...")
    try:
        r = gh_get("https://api.github.com/advisories?per_page=20&type=reviewed", 'GitHub-Advisories')
        new_items = []
        for adv in r.json():
            ghsa_id  = adv.get('ghsa_id', '')
            summary  = adv.get('summary', '')
            severity = adv.get('severity', 'unknown')
            html_url = adv.get('html_url', '')
            key      = f"ghsa_{ghsa_id}"
            if key not in seen and matches(summary):
                seen[key] = True
                new_items.append(f"* [{severity.upper()}] {summary}\n  {html_url}")
        if new_items:
            alert_all(f"GitHub Advisory: {len(new_items)} item(s)", new_items, severity='warning')
        else:
            print("[GitHub Advisories] nothing new")
        source_ok('GitHub-Advisories')
    except Exception as e:
        source_error('GitHub-Advisories', e)

def check_github_pocs(seen):
    print("[GitHub PoCs] checking...")
    try:
        cutoff = (datetime.date.today() - datetime.timedelta(days=3)).isoformat()
        new_items = []
        for kw in ['exploit rce', 'poc vulnerability', 'webshell']:
            url = (
                f"https://api.github.com/search/repositories"
                f"?q={kw.replace(' ','+')}+created:>{cutoff}&sort=updated&per_page=5"
            )
            r = gh_get(url, 'GitHub-PoCs')
            for repo in r.json().get('items', []):
                name = repo.get('full_name', '')
                desc = repo.get('description', '') or ''
                html = repo.get('html_url', '')
                key  = f"gh_{name}"
                mention(f"{name} {desc}", 'GitHub-PoC', html, f"{name}: {desc[:100]}")
                if key not in seen and matches(f"{name} {desc}"):
                    seen[key] = True
                    new_items.append(f"* {name}: {desc[:100]}\n  {html}")
        if new_items:
            alert_all(f"GitHub PoC: {len(new_items)} new repo(s)", new_items, severity='warning')
        else:
            print("[GitHub PoCs] nothing new")
        source_ok('GitHub-PoCs')
    except Exception as e:
        source_error('GitHub-PoCs', e)

def check_poc_in_github(seen):
    """GitHub search for new CVE-YYYY repos created in the last 24h."""
    print("[PoC-in-GitHub] checking...")
    try:
        year   = datetime.date.today().year
        cutoff = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
        url    = (
            f"https://api.github.com/search/repositories"
            f"?q=CVE-{year}+in:name+created:>{cutoff}&sort=stars&order=desc&per_page=10"
        )
        r = gh_get(url, 'PoC-in-GitHub')
        new_items = []
        for repo in r.json().get('items', []):
            name  = repo.get('full_name', '')
            desc  = repo.get('description', '') or ''
            html  = repo.get('html_url', '')
            stars = repo.get('stargazers_count', 0)
            key   = f"pocgh_{name}"
            mention(f"{name} {desc}", 'GitHub-PoC', html, f"{name}: {desc[:100]}")
            if key not in seen and (matches(f"{name} {desc}") or stars >= 1):
                seen[key] = True
                new_items.append(f"* {name} ⭐{stars}: {desc[:80]}\n  {html}")
        if new_items:
            alert_all(f"PoC-in-GitHub: {len(new_items)} new CVE repo(s)", new_items, severity='critical')
        else:
            print("[PoC-in-GitHub] nothing new")
        source_ok('PoC-in-GitHub')
    except Exception as e:
        source_error('PoC-in-GitHub', e)

def check_nuclei_templates(seen):
    """ProjectDiscovery nuclei-templates — new CVE templates mean a CVE is weaponized into a scanner."""
    print("[Nuclei Templates] checking...")
    try:
        cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)).strftime('%Y-%m-%dT%H:%M:%SZ')
        url    = (
            f"https://api.github.com/repos/projectdiscovery/nuclei-templates/commits"
            f"?path=http/cves&per_page=20&since={cutoff}"
        )
        r = gh_get(url, 'Nuclei-Templates')
        new_items = []
        for commit in r.json() if isinstance(r.json(), list) else []:
            sha     = commit.get('sha', '')[:8]
            message = commit.get('commit', {}).get('message', '').split('\n')[0]
            html    = commit.get('html_url', '')
            key     = f"nuclei_{sha}"
            if key not in seen and matches(message):
                seen[key] = True
                new_items.append(f"* {message[:100]}\n  {html}")
        if new_items:
            alert_all(f"Nuclei Templates: {len(new_items)} new CVE template(s)", new_items, severity='critical')
        else:
            print("[Nuclei Templates] nothing new")
        source_ok('Nuclei-Templates')
    except Exception as e:
        source_error('Nuclei-Templates', e)

def check_vulhub(seen):
    """Vulhub — new Docker PoC environments for CVEs added to the repo."""
    print("[Vulhub] checking...")
    try:
        cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=3)).strftime('%Y-%m-%dT%H:%M:%SZ')
        url    = f"https://api.github.com/repos/vulhub/vulhub/commits?per_page=15&since={cutoff}"
        r      = gh_get(url, 'Vulhub')
        new_items = []
        for commit in r.json() if isinstance(r.json(), list) else []:
            sha     = commit.get('sha', '')[:8]
            message = commit.get('commit', {}).get('message', '').split('\n')[0]
            html    = commit.get('html_url', '')
            key     = f"vulhub_{sha}"
            if key not in seen and matches(message):
                seen[key] = True
                new_items.append(f"* {message[:100]}\n  {html}")
        if new_items:
            alert_all(f"Vulhub: {len(new_items)} new PoC environment(s)", new_items, severity='critical')
        else:
            print("[Vulhub] nothing new")
        source_ok('Vulhub')
    except Exception as e:
        source_error('Vulhub', e)


def check_mitre_cve(seen):
    """MITRE CVEProject GitHub — CVEs at moment of assignment, days before NVD scores them."""
    print("[MITRE CVE] checking...")
    try:
        cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=8)).strftime('%Y-%m-%dT%H:%M:%SZ')
        url    = f"https://api.github.com/repos/CVEProject/cvelistV5/commits?per_page=50&since={cutoff}"
        r      = gh_get(url, 'MITRE-CVE')
        try:
            commits = r.json()
        except ValueError:
            print(f"[MITRE CVE] bad JSON: {r.text[:80]}")
            source_ok('MITRE-CVE')
            return
        new_cves = []
        for commit in (commits if isinstance(commits, list) else []):
            msg = commit.get('commit', {}).get('message', '')
            for cve_id in CVE_RE.findall(msg):
                cve_id = cve_id.upper()
                key    = f"mitre_{cve_id}"
                if key not in seen:
                    seen[key] = True
                    new_cves.append(cve_id)
                    track_cves(cve_id, 'MITRE')
        if new_cves:
            epss = enrich_epss(new_cves[:30])
            hot  = [(c, epss[c]) for c in new_cves if epss.get(c, 0) >= 0.2]
            if hot:
                lines = [f"* {c} EPSS:{e:.0%}" for c, e in sorted(hot, key=lambda x: -x[1])[:6]]
                alert(f"MITRE: {len(hot)} new CVE(s) EPSS≥20%", "\n".join(lines), severity='warning')
            print(f"[MITRE CVE] {len(new_cves)} new assigned, {len(hot)} with EPSS≥20%")
        else:
            print("[MITRE CVE] nothing new")
        source_ok('MITRE-CVE')
    except Exception as e:
        source_error('MITRE-CVE', e)

def check_nvd_high(seen):
    """NVD HIGH severity (CVSS 7.0-8.9) — catches serious vulns below CRITICAL threshold."""
    print("[NVD HIGH] checking...")
    try:
        now   = datetime.datetime.now(datetime.timezone.utc)
        since = (now - datetime.timedelta(days=2)).strftime('%Y-%m-%dT00:00:00.000')
        until = now.strftime('%Y-%m-%dT23:59:59.999')
        url   = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?pubStartDate={since}&pubEndDate={until}&cvssV3Severity=HIGH"
        )
        r    = requests.get(url, headers=HEADERS, timeout=20)
        candidates = []
        for item in r.json().get('vulnerabilities', []):
            cve    = item.get('cve', {})
            cve_id = cve.get('id', '')
            descs  = cve.get('descriptions', [])
            desc   = next((d['value'] for d in descs if d['lang'] == 'en'), '')
            score  = 0
            try:
                score = item['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
            except Exception:
                pass
            key = f"nvd_high_{cve_id}"
            if key not in seen and score >= 7.0 and matches(desc):
                candidates.append((key, cve_id, score, desc))
        if not candidates:
            print("[NVD HIGH] nothing new")
            source_ok('NVD-HIGH')
            return
        epss = enrich_epss([c[1] for c in candidates])
        new_items = []
        for key, cve_id, score, desc in candidates:
            seen[key] = True
            ep     = epss.get(cve_id)
            ep_str = f" EPSS:{ep:.0%}" if ep is not None else ""
            new_items.append(f"* {cve_id} CVSS:{score}{ep_str} — {desc[:110]}")
            track_cves(cve_id, 'NVD-HIGH')
        alert_all(f"NVD HIGH: {len(new_items)} CVE(s)", new_items, severity='warning')
        source_ok('NVD-HIGH')
    except Exception as e:
        source_error('NVD-HIGH', e)

def check_mastodon(seen):
    """infosec.exchange — security researchers post active exploits and 0days here before anywhere else."""
    print("[Mastodon] checking...")
    try:
        # v2.5: page forward from the last post read (min_id), so no post falls between two checks;
        # at most 5 pages (200 posts) per check.
        api  = 'https://infosec.exchange/api/v1/timelines/public'
        last = seen.get('_masto_min_id')
        statuses = []
        for _ in range(5 if last else 1):
            params = {'local': 'true', 'limit': 40}
            if last:
                params['min_id'] = last
            r = requests.get(api, params=params, headers=HEADERS, timeout=15)
            if r.status_code == 429:
                print("[Mastodon] rate limited — the rest waits for the next check")
                break
            r.raise_for_status()
            batch = r.json() if isinstance(r.json(), list) else []
            if not batch:
                break
            statuses.extend(batch)
            last = str(max(int(s['id']) for s in batch))
            if len(batch) < 40:
                break
        if statuses:
            seen['_masto_min_id'] = str(max(int(s['id']) for s in statuses))
        urgent, news = [], []
        for status in statuses:
            sid     = status.get('id', '')
            content = ' '.join(html.unescape(re.sub(r'<[^>]+>', ' ', status.get('content', ''))).split())
            url     = status.get('url', '')
            who     = (status.get('account') or {}).get('acct', '')
            key     = f"mastodon_{sid}"
            track_cves(content, 'Mastodon')
            mention(content, 'Mastodon', url, content[:160])
            if key in seen or not is_security_story(content):
                continue
            seen[key] = True
            if is_urgent(content):
                urgent.append(f"* @{who}: {content[:200]}\n  {enrich(content, 'infosec.exchange post')[:900]}\n  {url}")
            else:
                news.append(f"* @{who}: {content[:200]}\n  {url}")
        if urgent:
            alert_all(f"infosec.exchange: {len(urgent)} urgent — your critical gear", urgent, severity='critical')
        if news:
            _cycle_digest.extend(f"[Mastodon] {l}" for l in news)
        print(f"[Mastodon] {len(statuses)} new posts, {len(urgent)} urgent, {len(news)} to the digest")
        source_ok('Mastodon')
    except Exception as e:
        source_error('Mastodon', e)

# v2.2: a release counts as a security release only when its notes carry one of these words (whole words)
# or a CVE id. "fix" and "patch" were in the list until 2026-10-22 — every Home Assistant release is a list of
# "Fix …" lines, so each one, betas included, went out as critical ("way too many patches"). Betas are skipped:
# the house runs releases.
RELEASE_SEC_WORDS = ('security', 'vulnerability', 'rce', 'remote code', 'arbitrary code', 'auth bypass',
                     'authentication bypass', 'privilege escalation', 'injection')
_RELEASE_SEC_RE = re.compile(r'\b(' + '|'.join(re.escape(w) for w in RELEASE_SEC_WORDS) + r')\b')

def release_security_hits(body):
    """The security words and CVE ids a release's notes mention — empty for a plain bug-fix release."""
    b = (body or '').lower()
    words = sorted(set(_RELEASE_SEC_RE.findall(b)), key=RELEASE_SEC_WORDS.index)
    return words + sorted({c.upper() for c in CVE_RE.findall(b)})

def check_product_releases(seen):
    """Monitor GitHub releases for products in the stack — alert on the ones whose notes mention security."""
    print("[Product Releases] checking...")
    PRODUCTS = [
        ('home-assistant/core',              'Home-Assistant'),
        ('ollama/ollama',                    'Ollama'),
        ('openssh/openssh-portable',         'OpenSSH'),
        ('kubernetes/kubernetes',            'Kubernetes'),
        ('nginx/nginx',                      'Nginx'),
        ('php/php-src',                      'PHP'),
        ('docker/docker-ce',                 'Docker'),
    ]
    new_items = []
    for repo, label in PRODUCTS:
        try:
            r = gh_get(f"https://api.github.com/repos/{repo}/releases?per_page=5", f"Release-{label}")
            for rel in (r.json() if isinstance(r.json(), list) else []):
                if rel.get('prerelease') or rel.get('draft'):
                    continue
                tag  = rel.get('tag_name', '')
                html = rel.get('html_url', '')
                key  = f"release_{repo}_{tag}"
                if key in seen:
                    continue
                seen[key] = True                                   # noted once, security notes or not
                hits = release_security_hits(rel.get('body', ''))
                if hits:
                    has_cve = any(h.startswith('CVE-') for h in hits)
                    new_items.append((has_cve, f"* {label} {tag} — mentions {', '.join(hits[:4])}\n  {html}"))
        except Exception as e:
            source_error(f"Release-{label}", e)
    if new_items:
        sev = 'critical' if any(c for c, _ in new_items) else 'warning'
        alert_all(f"Product Release: {len(new_items)} with security notes", [t for _, t in new_items], severity=sev)
    else:
        print("[Product Releases] nothing new")
    source_ok('Product-Releases')

def check_sploitus(seen):
    """Sploitus — exploit aggregator (EDB + PacketStorm + others in one search)."""
    print("[Sploitus] checking...")
    try:
        new_items = []
        for kw in KEYWORDS[:6]:
            r = requests.post(
                'https://sploitus.com/search',
                json={'type': 'exploits', 'query': kw, 'sort': 'default', 'offset': 0},
                headers={**HEADERS, 'Content-Type': 'application/json', 'Accept': 'application/json'},
                timeout=15
            )
            if r.status_code != 200:
                continue
            try:
                sdata = r.json()
            except ValueError:
                continue
            for ex in sdata.get('exploits', [])[:5]:
                title   = ex.get('title', '')
                href    = ex.get('href', '') or ex.get('source', '')
                eid     = ex.get('id', '') or ex.get('hash', title[:32])
                desc    = (ex.get('description', '') or '').strip()[:160]
                cve_str = ex.get('cve_string', '')
                epss    = ex.get('epss_score')
                key     = f"sploitus_{eid}"
                if key not in seen and matches(title):
                    seen[key] = True
                    meta = ' · '.join(filter(None, [cve_str, f"EPSS:{epss:.0%}" if epss else '']))
                    line = f"* {title}"
                    if meta:
                        line += f" [{meta}]"
                    if desc:
                        line += f"\n  {desc}"
                    line += f"\n  {href}"
                    new_items.append(line)
        if new_items:
            alert_all(f"Sploitus: {len(new_items)} exploit(s)", new_items, severity='critical')
        else:
            print("[Sploitus] nothing new")
        source_ok('Sploitus')
    except Exception as e:
        source_error('Sploitus', e)

def check_hackernews_algolia(seen):
    print("[HackerNews] checking...")
    try:
        # v2.5: one call for EVERY story since the last check (was: 5 keyword searches covering only the first 5
        # products of 106). The window starts 10 minutes before the last check, at most 12 hours back.
        now   = time.time()
        start = max(now - 12 * 3600, float(seen.get('_hn_since_ts', now - 6 * 3600)) - 600)
        r = requests.get('https://hn.algolia.com/api/v1/search_by_date', headers=HEADERS, timeout=15,
                         params={'tags': 'story', 'numericFilters': f'created_at_i>{int(start)}', 'hitsPerPage': 1000})
        r.raise_for_status()
        hits = r.json().get('hits', [])
        seen['_hn_since_ts'] = now
        urgent, news = [], []
        for hit in hits:
            oid   = hit.get('objectID', '')
            title = hit.get('title') or ''
            disc  = f"https://news.ycombinator.com/item?id={oid}"
            link  = hit.get('url') or disc
            mention(title, 'HackerNews', disc, title)
            key = f"hn_{oid}"
            if key in seen or not is_security_story(title):
                continue
            seen[key] = True
            line = f"* {title} (▲{hit.get('points') or 0} 💬{hit.get('num_comments') or 0})\n  {link}"
            if link != disc:
                line += f"\n  {disc}"
            if is_urgent(title):
                urgent.append(line.replace('\n', f"\n  {enrich(title, 'Hacker News story')[:700]}\n", 1))
            else:
                news.append(line)
        if urgent:
            alert_all(f"HackerNews: {len(urgent)} urgent — your critical gear", urgent, severity='critical')
        if news:
            _cycle_digest.extend(f"[HackerNews] {l}" for l in news)
        print(f"[HackerNews] {len(hits)} stories, {len(urgent)} urgent, {len(news)} to the digest")
        source_ok('HackerNews')
    except Exception as e:
        source_error('HackerNews', e)

# ── v2.6 (S2): more ears, no tokens ──────────────────────────────────────────────────────────────────────────
GOOGLE_NEWS_ON = cfg.get('news', 'google_news', fallback='on').strip().lower() not in ('off', 'no', 'false', '0')
TG_CHANNELS = [c.strip().lstrip('@') for c in cfg.get('news', 'telegram_channels', fallback='cvenotify').split(',') if c.strip()]
# Channels that just repeat every new CVE (like a database): they speed up "critical gear" items, but never count
# as an independent source for "Confirmed" and never fill the digest with every WordPress plugin.
TG_CVE_BOTS = {c.strip().lstrip('@').lower() for c in cfg.get('news', 'telegram_cve_bots', fallback='cvenotify').split(',') if c.strip()}
BROWSER_UA = {'User-Agent': REDDIT_HEADERS['User-Agent']}

def _gn_queries():
    """Google News searches: the exploitation words on their own, then the critical products in groups of 8 next
    to an attack word — 6 searches cover all 37 critical products. when:1d = only the last day."""
    q = lambda n: f'"{n}"' if ' ' in n else n
    attack = '(exploit OR exploited OR "zero-day" OR vulnerability OR CVE)'
    out = ['"actively exploited" OR "exploited in the wild" OR "zero-day exploit" OR "mass exploitation"',
           'site:cisa.gov/news-events',                     # v3.3: CISA blocks direct readers; its advisories via Google
           '"Windows 11" (update OR KB) ("known issue" OR breaks OR broken OR bug OR BSOD OR "boot" OR BitLocker OR Defender)']
    names = _CRITICAL_NAMES or _PRODUCT_NAMES[:16]
    for i in range(0, len(names), 8):
        out.append(f"({' OR '.join(q(n) for n in names[i:i + 8])}) {attack}")
    return [f"{x} when:{'3d' if x.startswith('site:') else '1d'}" for x in out]   # Google indexes cisa.gov late

def check_google_news(seen):
    """Google News RSS search: hundreds of outlets in one place, including the ones that pick up X posts first."""
    print("[GoogleNews] checking...")
    today = datetime.date.today().isoformat()
    if not GOOGLE_NEWS_ON or _demoted.get('GoogleNews') == today:
        print("[GoogleNews] off" if not GOOGLE_NEWS_ON else "[GoogleNews] resting today (rate limited earlier)")
        return
    try:
        import urllib.parse, email.utils
        urgent, news, n_items = [], [], 0
        pool = []                                                  # v3.3: word sets of the headlines kept this run
        priming = not seen.get('_gn_primed')                       # first ever run: remember, don't flood
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=36)
        for query in _gn_queries():
            url = f"https://news.google.com/rss/search?q={urllib.parse.quote(query)}&hl=en-US&gl=US&ceid=US:en"
            r = requests.get(url, headers=BROWSER_UA, timeout=15)
            if r.status_code in (429, 503):
                _demoted['GoogleNews'] = today
                print(f"[GoogleNews] HTTP {r.status_code} — resting for the rest of today")
                break
            r.raise_for_status()
            root = parse_xml_robust(r.content)
            for item in (root.findall('.//item') if root is not None else []):
                n_items += 1
                title = (item.findtext('title') or '').strip()
                link  = (item.findtext('link') or '').strip()
                try:
                    if email.utils.parsedate_to_datetime(item.findtext('pubDate') or '') < cutoff:
                        continue
                except (TypeError, ValueError):
                    pass
                headline, _, outlet = title.rpartition(' - ')
                headline = headline or title
                key = 'gnews_' + re.sub(r'[^a-z0-9]+', ' ', headline.lower()).strip()[:120]
                track_cves(headline, 'GoogleNews')
                mention(headline, 'GoogleNews', link, title)
                cisa = query.startswith('site:cisa.gov')
                if key in seen or not (cisa or is_security_story(headline)):
                    continue
                seen[key] = True
                words = _headline_words(headline)
                if any(len(words & w) / max(1, len(words | w)) >= 0.5 for w in pool):
                    continue                                       # the same story from another outlet
                pool.append(words)
                if priming:
                    continue
                line = f"* {headline}" + (f" ({outlet})" if outlet else '') + f"\n  {link}"
                if is_urgent(headline):
                    urgent.append(line.replace('\n', f"\n  {enrich(headline, 'Google News headline')[:700]}\n", 1))
                else:
                    news.append(line)
        if priming and n_items:
            seen['_gn_primed'] = True
            print("[GoogleNews] first run: today's stories remembered, alerts from the next check on")
        if urgent:
            alert_all(f"Google News: {len(urgent)} urgent — your critical gear", urgent, severity='critical')
        if news:
            _cycle_digest.extend(f"[GoogleNews] {l}" for l in news)
        print(f"[GoogleNews] {n_items} items, {len(urgent)} urgent, {len(news)} to the digest")
        source_ok('GoogleNews')
    except Exception as e:
        source_error('GoogleNews', e)

_STRONG_RE = re.compile(r'(?i)(?<!can be )(?<!could be )(?<!may be )(?<!might be )\bexploited\b|in the wild|actively|pre-?auth|unauthenticated[^.]{0,80}'
                        r'(?:remote code|code execution|command (?:execution|injection)|rce)')
_STOP = {'the', 'and', 'for', 'with', 'from', 'that', 'this', 'are', 'was', 'has', 'have', 'new', 'into', 'over',
         'after', 'amid', 'its', 'your', 'you', 'how', 'why', 'what', 'who', 'says', 'said', 'via', 'now'}

def _headline_words(text):
    return {w for w in re.findall(r'[a-z0-9][a-z0-9.-]{2,}', text.lower()) if w not in _STOP}

_TG_POST_RE = re.compile(r'data-post="([^"/]+)/(\d+)".*?<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', re.S)

def check_telegram(seen):
    """Public Telegram channels through their t.me/s/ web page: no account, no bot, no phone number. Only the words
    of the posts are read — never files or links. Pages back until the last post read (at most 5 pages)."""
    print("[Telegram] checking...")
    try:
        urgent, news, n_new = [], [], 0
        for ch in TG_CHANNELS:
            last = int(seen.get(f'_tg_last_{ch.lower()}', 0))
            posts, before = {}, None
            for _ in range(5 if last else 1):
                url = f"https://t.me/s/{ch}" + (f"?before={before}" if before else '')
                r = requests.get(url, headers=BROWSER_UA, timeout=15)
                if r.status_code == 429:
                    print(f"[Telegram] {ch}: rate limited")
                    break
                r.raise_for_status()
                page = {int(pid): body for _, pid, body in _TG_POST_RE.findall(r.text)}
                if not page:
                    break
                posts.update(page)
                before = min(page)
                if before <= last:
                    break
            new = sorted(pid for pid in posts if pid > last)
            if posts:
                seen[f'_tg_last_{ch.lower()}'] = max(posts)
            if not last:                                     # first read of a channel: remember, don't flood
                print(f"[Telegram] {ch}: primed at post {max(posts) if posts else 0}")
                continue
            bot = ch.lower() in TG_CVE_BOTS
            for pid in new:
                n_new += 1
                text = ' '.join(html.unescape(re.sub(r'<[^>]+>', ' ', posts[pid])).split())
                link = f"https://t.me/{ch}/{pid}"
                track_cves(text, f"Telegram:{ch}")
                if not bot:
                    mention(text, f"Telegram:{ch}", link, text[:160])
                critical_gear = bool(_CRITICAL_RE and _CRITICAL_RE.search(text.lower())) and not _NOISE_RE.search(text)
                if bot and not critical_gear:
                    continue
                if not bot and not is_security_story(text):
                    continue
                line = f"* @{ch}: {text[:220]}\n  {link}"
                # every CVE text says "vulnerability", "critical", "bypass": from a CVE bot only strong signals are urgent
                strong = (not bot) or bool(_STRONG_RE.search(text))
                if strong and is_urgent(text):
                    urgent.append(line.replace('\n', f"\n  {enrich(text, f'Telegram @{ch}')[:700]}\n", 1))
                else:
                    news.append(line)
        if urgent:
            alert_all(f"Telegram: {len(urgent)} urgent — your critical gear", urgent, severity='critical')
        if news:
            _cycle_digest.extend(f"[Telegram] {l}" for l in news)
        print(f"[Telegram] {n_new} new posts, {len(urgent)} urgent, {len(news)} to the digest")
        source_ok('Telegram')
    except Exception as e:
        source_error('Telegram', e)

_SYNO_RE  = re.compile(r'href="security/advisory/(Synology_SA_\d+_\d+)">\s*([^<]*?\S[^<]*?)\s*<')   # the link WITH text
_SYNO_SEV = re.compile(r'Critical|Important|Moderate|Low|Not Affected')

def check_synology(seen):
    """Synology has no feed: the advisory list page is read and new advisory ids are alerted, with their severity."""
    print("[Synology-SA] checking...")
    try:
        r = requests.get('https://www.synology.com/en-global/security/advisory', headers=BROWSER_UA, timeout=20)
        r.raise_for_status()
        found = {}
        for m in _SYNO_RE.finditer(r.text):                        # two links per advisory; one has no text
            sev = _SYNO_SEV.search(r.text, m.end(), m.end() + 1500)
            found.setdefault(m.group(1), (' '.join(m.group(2).split()), sev.group(0) if sev else '?'))
        if not found:
            raise ValueError("no advisory ids on the page — its layout changed")
        known = set(seen.get('_watch_synology', []))
        new = sorted(set(found) - known)
        seen['_watch_synology'] = sorted(known | set(found))[-300:]
        if known and new:
            lines = []
            for sid in new:
                title, sev = found[sid]
                lines.append(f"* {title} [{sev}]\n  {enrich(title, 'Synology advisory', use_ai=False)}\n"
                             f"  https://www.synology.com/en-global/security/advisory/{sid}")
            sev = 'critical' if any(found[s][1] == 'Critical' for s in new) else 'warning'
            alert_all(f"Synology: {len(new)} new advisory(ies)", lines, severity=sev)
        print(f"[Synology-SA] {len(found)} on the page, {len(new) if known else 0} new")
        source_ok('Synology-SA')
    except Exception as e:
        source_error('Synology-SA', e)

def check_mikrotik(seen):
    """MikroTik has no feed: when RouterOS 7 stable gets a new version, its CHANGELOG is read and the lines that
    name a CVE or a vulnerability are alerted (critical gear)."""
    print("[MikroTik] checking...")
    try:
        r = requests.get('https://upgrade.mikrotik.com/routeros/NEWESTa7.stable', headers=HEADERS, timeout=15)
        r.raise_for_status()
        ver = (r.text.split() or [''])[0]
        if not re.fullmatch(r'\d+(?:\.\d+){1,3}', ver):
            raise ValueError(f"unexpected version text: {r.text[:40]!r}")
        prev = seen.get('_watch_mikrotik')
        seen['_watch_mikrotik'] = ver
        if prev and prev != ver:
            log = requests.get(f'https://upgrade.mikrotik.com/routeros/{ver}/CHANGELOG', headers=HEADERS, timeout=15).text
            sec = [l.strip() for l in log.splitlines() if re.search(r'(?i)CVE-\d|vulnerab|security fix|security issue', l)]
            url = f"https://mikrotik.com/download/changelogs"
            if sec:
                body = [f"* RouterOS {ver} stable (was {prev}) fixes:"] + [f"  {l}" for l in sec[:15]] + [f"  {url}"]
                alert_all(f"MikroTik RouterOS {ver}: security fixes", body, severity='critical', routine=False)
            else:
                print(f"[MikroTik] {ver} released, no security lines in the changelog")
        print(f"[MikroTik] stable {ver}" + (f" (was {prev})" if prev and prev != ver else ''))
        source_ok('MikroTik')
    except Exception as e:
        source_error('MikroTik', e)

# ── v2.6b: Windows — Microsoft's own exploitation flags ──────────────────────────────────────────────────────
_MS_KEEP = ('Windows Server', 'Exchange Server', 'SQL Server', 'SharePoint', 'Windows 11', 'Windows 10', 'Hyper-V',
            'Office', 'Microsoft 365', 'Entra', 'Defender', '.NET', 'Remote Desktop')

def _ms_products(names):
    """The affected products worth naming: servers first, at most 5, versions folded ("Windows Server 2019, 2022")."""
    keep = {n.replace(' (Server Core installation)', '') for n in names if any(k in n for k in _MS_KEEP)}
    wsrv = sorted({n[len('Windows Server '):].split(' ')[0] + (' R2' if ' R2' in n else '')
                   for n in keep if n.startswith('Windows Server 20')})
    rest = sorted({re.split(r' (?:for|on|installed) ', n)[0][:45] for n in keep if not n.startswith('Windows Server 20')},
                  key=lambda n: (0 if 'Server' in n else 1, n))
    parts = ([f"Windows Server {', '.join(wsrv)}"] if wsrv else []) + rest
    if not parts:                                   # names outside the list above: show them, shortened
        parts = sorted({re.split(r' (?:for|on|installed) ', n)[0][:45] for n in names if n})
    return ', '.join(parts[:4]) + (f' +{len(parts) - 4} more' if len(parts) > 4 else '')

def check_msrc(seen):
    """Microsoft Security Update Guide (CVRF API): every CVE with Microsoft's own "Exploited: Yes" and "Publicly
    Disclosed" flags and the affected products. The 47 KB update list is read every fast check; a month's document
    (~20 MB) only when Microsoft revised it. Exploited → critical at once; publicly disclosed → warning; critical
    "Exploitation More Likely" on Windows Server → digest. The first run only remembers."""
    print("[MSRC-CVRF] checking...")
    try:
        H = dict(HEADERS, Accept='application/json')
        r = requests.get('https://api.msrc.microsoft.com/cvrf/v3.0/updates', headers=H, timeout=20)
        r.raise_for_status()
        months = sorted(r.json().get('value', []), key=lambda u: u.get('InitialReleaseDate', ''))[-3:]
        priming = not seen.get('_msrc_primed')
        exploited, disclosed, likely, read = [], [], [], 0
        for m in months:
            rev_key = f"_msrc_rev_{m['ID']}"
            if seen.get(rev_key) == m.get('CurrentReleaseDate'):
                continue
            doc = requests.get(m['CvrfUrl'], headers=H, timeout=120)
            doc.raise_for_status()
            d = doc.json()
            read += 1
            month_stats = {'critical': 0, 'likely': 0, 'exploited': [], 'disclosed': [], 'server': [], 'items': []}
            names = {p['ProductID']: p['Value'] for p in d.get('ProductTree', {}).get('FullProductName', [])}
            for v in d.get('Vulnerability', []):
                cve = v.get('CVE', '')
                title = (v.get('Title') or {}).get('Value', '')
                status, sev = '', ''
                for t in v.get('Threats', []):
                    val = (t.get('Description') or {}).get('Value', '')
                    if t.get('Type') == 1 and not status:
                        status = val
                    elif t.get('Type') == 3 and val in ('Critical', 'Important') and sev != 'Critical':
                        sev = val
                scores = [s.get('BaseScore', 0) for s in v.get('CVSSScoreSets', [])]
                cvss = max(scores) if scores else None
                affected = [names.get(pid, '') for ps in v.get('ProductStatuses', []) if ps.get('Type') == 3
                            for pid in ps.get('ProductID', [])]
                prods = _ms_products(affected)
                link = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
                head = f"{cve} {title}" + (f" [{sev}" + (f", CVSS {cvss}" if cvss else '') + "]" if sev else '')
                if 'Exploited:Yes' in status and f"msrc_exp_{cve}" not in seen:
                    seen[f"msrc_exp_{cve}"] = True
                    if not priming:
                        track_cves(cve, 'MSRC'); mention(f"{cve} {title}", 'MSRC', link, title)
                        brief = enrich(f"{title}. Microsoft: exploitation detected. Severity {sev}. CVSS {cvss}. "
                                       f"Affected: {prods}.", 'Microsoft Security Update Guide')
                        exploited.append(f"* {head}\n  Affects: {prods or 'see link'}\n  {brief[:800]}\n  {link}")
                elif 'Publicly Disclosed:Yes' in status and f"msrc_pub_{cve}" not in seen:
                    seen[f"msrc_pub_{cve}"] = True
                    if not priming:
                        mention(f"{cve} {title}", 'MSRC', link, title)
                        disclosed.append(f"* {head}\n  Affects: {prods or 'see link'}\n  {link}")
                elif ((sev == 'Critical' or 'Exploitation More Likely' in status)          # v2.7: all of them
                      and f"msrc_likely_{cve}" not in seen):
                    seen[f"msrc_likely_{cve}"] = True
                    if not priming:
                        tag = ' — exploitation more likely' if 'Exploitation More Likely' in status else ''
                        likely.append(f"* {head}{tag}\n  Affects: {prods or 'see link'}\n  {link}")
                if sev == 'Critical':
                    month_stats['critical'] += 1
                if 'Exploited:Yes' in status:
                    month_stats['exploited'].append(cve)
                if 'Publicly Disclosed:Yes' in status:
                    month_stats['disclosed'].append(cve)
                if 'Exploitation More Likely' in status:
                    month_stats['likely'] += 1
                if 'Windows Server' in prods and (sev == 'Critical' or 'Exploited:Yes' in status):
                    month_stats['server'].append(f"{cve} {title[:70]}")
                flags = [f for f, on in (('EXPLOITED', 'Exploited:Yes' in status),
                                         ('publicly disclosed', 'Publicly Disclosed:Yes' in status),
                                         ('more likely', 'Exploitation More Likely' in status)) if on]
                if sev == 'Critical' or flags:
                    month_stats['items'].append(f"{cve} {title} [{sev or '?'}{', CVSS ' + str(cvss) if cvss else ''}"
                                                f"{', ' + ', '.join(flags) if flags else ''}] affects: {prods or '?'}")
            seen[rev_key] = m.get('CurrentReleaseDate')
            if f"_msrc_month_{m['ID']}" not in seen:                     # v2.7: Patch Tuesday, the whole month
                seen[f"_msrc_month_{m['ID']}"] = True
                if not priming:
                    total = len(d.get('Vulnerability', []))
                    body = [f"* {m.get('DocumentTitle', m['ID'])}: {total} CVEs — {month_stats['critical']} Critical, "
                            f"{len(month_stats['exploited'])} exploited, {len(month_stats['disclosed'])} publicly "
                            f"disclosed, {month_stats['likely']} 'exploitation more likely'"]
                    if month_stats['exploited']:
                        body.append(f"  Exploited: {', '.join(month_stats['exploited'])}")
                    if month_stats['disclosed']:
                        body.append(f"  Disclosed: {', '.join(month_stats['disclosed'][:8])}")
                    if month_stats['server']:
                        body.append(f"  Windows Server, Critical or exploited ({min(15, len(month_stats['server']))} of "
                                    f"{len(month_stats['server'])}):")
                        body.extend(f"  • {x}" for x in month_stats['server'][:15])
                    body.append("  https://msrc.microsoft.com/update-guide/releaseNote/" + m['ID'])
                    order = ai_call(_ANALYST, f"{_PATCH_TUESDAY_SHAPE}\n\n{m.get('DocumentTitle', m['ID'])}, "
                                    f"{len(month_stats['items'])} notable CVEs:\n" + '\n'.join(month_stats['items'][:250]),
                                    max_tokens=6000, effort='medium', model=BRIEF_MODEL, timeout=180.0)
                    if order:
                        body = [l for l in order.splitlines() if l.strip()] + ['', '— the numbers —'] + body
                    alert_all(f"Patch Tuesday {m['ID']}: {total} CVEs, {len(month_stats['exploited'])} exploited",
                              body, severity='critical' if month_stats['exploited'] else 'warning', routine=False)
        if priming and read:
            seen['_msrc_primed'] = True
            print("[MSRC-CVRF] first run: the last 3 months remembered, alerts from the next revision on")
        if exploited:
            alert_all(f"Microsoft: {len(exploited)} CVE(s) exploited in the wild", exploited, severity='critical', routine=False)
        if disclosed:
            alert_all(f"Microsoft: {len(disclosed)} CVE(s) publicly disclosed", disclosed, severity='warning')
        if likely:
            _cycle_digest.extend(f"[MSRC] {l}" for l in likely)
        print(f"[MSRC-CVRF] {read} month(s) re-read, {len(exploited)} exploited, {len(disclosed)} disclosed, "
              f"{len(likely)} likely")
        source_ok('MSRC-CVRF')
    except Exception as e:
        source_error('MSRC-CVRF', e)

def check_kernel_releases(seen):
    """kernel.org: a new stable or longterm kernel goes into the digest (the long-term lines are what servers run)."""
    print("[Kernel-releases] checking...")
    try:
        r = requests.get('https://www.kernel.org/releases.json', headers=HEADERS, timeout=15)
        r.raise_for_status()
        rels = [x for x in r.json().get('releases', []) if x.get('moniker') in ('stable', 'longterm')]
        prev = seen.get('_kernel_versions')
        now = {x['version'].rsplit('.', 1)[0] if x['version'].count('.') > 1 else x['version']: x['version'] for x in rels}
        seen['_kernel_versions'] = now
        new = [f"* Linux {v} ({x['moniker']}, {x.get('released', {}).get('isodate', '')})\n  "
               f"https://cdn.kernel.org/pub/linux/kernel/v{v.split('.')[0]}.x/ChangeLog-{v}"
               for x in rels for v in [x['version']] if prev is not None and prev.get(
                   v.rsplit('.', 1)[0] if v.count('.') > 1 else v) != v]
        if new:
            _cycle_digest.extend(f"[Kernel-releases] {l}" for l in new)
        print(f"[Kernel-releases] {len(rels)} lines, {len(new)} new")
        source_ok('Kernel-releases')
    except Exception as e:
        source_error('Kernel-releases', e)

# ── v2.6b: Linux — this PC's own patch state ─────────────────────────────────────────────────────────────────

# ── v3.6: all his PCs (three Zorin), and the fix tracker ─────────────────────────────────────────────────────────
# Each PC runs scout_pc.py by cron: its patch state lands on the private topic <ctl>-pc. The home Scout (and the cloud)
# read it every slow cycle, warn when a PC lags, and the fix tracker asks Ubuntu's CVE tracker about every open Linux
# CVE that touched home; when the fix ships it says which PC still runs the old kernel.
PC_SILENT_DAYS = 3
FIX_WATCH = [c.strip().upper() for c in cfg.get('fixes', 'watch', fallback='').split(',') if c.strip()]

def _pc_topic():
    return cfg.get('ntfy', 'pc_topic', fallback='').strip() or f"{_ctl_topic()}-pc"

def _kver(s):
    """'7.0.0-43.43~24.04.1' or '7.0.0-42-generic' → (7, 0, 0, 43) for comparing."""
    m = re.match(r'(\d+)\.(\d+)\.(\d+)-(\d+)', s or '')
    return tuple(int(x) for x in m.groups()) if m else ()

def _open_cve_add(cves, title):
    seen = _seen()
    oc = seen.setdefault('_open_cves', {})
    year = datetime.date.today().year
    for c in [c.upper() for c in cves if int(c.split('-')[1]) >= year - 1][:3]:   # v3.6: old CVEs re-told are not open
        if c not in oc and len(oc) < 25:
            oc[c] = {'t': time.time(), 'title': title[:80], 'state': {}, 'miss': 0}
            print(f"[fixes] watching {c} until a fix ships")

def check_pcs(seen):
    """The fleet: this PC directly (home only), the others from the PC topic. Warns once a day per PC that has
    security updates waiting > 24 h, a reboot pending > 48 h, or has not reported for PC_SILENT_DAYS."""
    pcs = seen.setdefault('_pcs', {})
    now = time.time()
    if not _state.get('cloud'):
        try:
            import importlib
            spc = importlib.import_module('scout_pc')
            d = spc.collect()
            pcs[d['host']] = {**pcs.get(d['host'], {}), **d, 'via': 'local'}
        except Exception as e:
            print(f"[PCs] local state not read: {e}")
    try:
        r = requests.get(f"{NTFY_SERVER}/{_pc_topic()}/json",
                         params={'poll': '1', 'since': int(now - 8 * 86400)}, timeout=20)
        r.raise_for_status()
        for raw in r.text.splitlines():
            try:
                ev = json.loads(raw)
                d = json.loads(ev.get('message') or '') if ev.get('event') == 'message' else None
            except ValueError:
                continue
            if not isinstance(d, dict) or not d.get('host') or not d.get('kernel'):
                continue
            h = d['host'][:40]
            if d.get('t', 0) >= pcs.get(h, {}).get('t', 0) and pcs.get(h, {}).get('via') != 'local':
                pcs[h] = {**pcs.get(h, {}), **d, 'via': 'topic'}
    except Exception as e:
        print(f"[PCs] topic not read: {e}")
    today = datetime.date.today().isoformat()
    lines, summary = [], []
    for h, d in sorted(pcs.items()):
        age_d = (now - d.get('t', 0)) / 86400
        sec = d.get('sec_updates') or []
        if sec:
            d.setdefault('sec_since', d.get('t', now))
        else:
            d.pop('sec_since', None)
        if age_d > PC_SILENT_DAYS:
            summary.append(f"{h} silent {age_d:.0f} d")
            lines.append(f"* {h}: no report for {age_d:.0f} days — off, or scout_pc.py's cron is gone")
            continue
        state = f"{len(sec)} security update(s)" if sec else "ok"
        if d.get('reboot_h'):
            state += ", reboot needed"
        summary.append(f"{h} {state}")
        if sec and now - float(d['sec_since']) > 24 * 3600:
            lines.append(f"* {h} ({d.get('os', '')}): {len(sec)} security update(s) waiting for over a day: "
                         f"{', '.join(sec[:10])}\n  sudo apt update && sudo apt upgrade")
        if (d.get('reboot_h') or 0) > 48:
            lines.append(f"* {h}: reboot needed for {d['reboot_h'] / 24:.0f} day(s) — kernel {d.get('kernel')} still "
                         f"running, installed: {', '.join(d.get('kernels_installed', [])[-2:])}")
    _last_health['pc'] = f"{len(pcs)} PC(s): " + '; '.join(summary) if pcs else ''
    if lines and seen.get('_pcs_warned') != today:
        seen['_pcs_warned'] = today
        alert_all("PCs: patches not applied", lines, severity='warning', routine=False)
    print(f"[PCs] {_last_health['pc'] or 'none reported yet'}")

def _fix_lines_for(cve, pkg, codename, fixver, pcs):
    """Who still needs the kernel fix: one line per PC on that release."""
    out, want = [], _kver(fixver)
    for h, d in sorted(pcs.items()):
        if d.get('codename') and d['codename'] != codename:
            continue
        if not pkg.startswith('linux') or not want:
            out.append(f"  {h}: sudo apt update && sudo apt upgrade")
            continue
        run, inst = _kver(d.get('kernel', '')), max([_kver(k) for k in d.get('kernels_installed', [])] or [()])
        if run >= want:
            out.append(f"  {h}: already running {d.get('kernel')} ✓")
        elif inst >= want:
            out.append(f"  {h}: fix installed, REBOOT to load it (running {d.get('kernel')})")
        else:
            out.append(f"  {h}: running {d.get('kernel')} → sudo apt update && sudo apt upgrade, then reboot")
    return out

_BASE_KERNEL = {'jammy': '5.15', 'noble': '6.8', 'resolute': '7.0'}     # the release's own kernel; anything else is HWE

def _kernel_pkgs(pcs, codename):
    """The Ubuntu kernel source packages his PCs on this release actually run: 'linux' for the release's own kernel,
    'linux-hwe-X.Y' for a newer one, plus oem/lowlatency when the kernel name says so."""
    out = set()
    for d in pcs.values():
        if d.get('codename') and d['codename'] != codename:
            continue
        k = d.get('kernel', '')
        m = re.match(r'(\d+\.\d+)\.', k)
        if not m:
            continue
        mm = m.group(1)
        base = 'linux' if mm == _BASE_KERNEL.get(codename) else f'linux-hwe-{mm}'
        if 'oem' in k:
            base = f'linux-oem-{mm}'
        elif 'lowlatency' in k:
            base = base.replace('linux', 'linux-lowlatency', 1)
        out.add(base)
    return out or {'linux', 'linux-hwe-7.0'}

def track_fixes(seen):
    """Ubuntu's CVE tracker (ubuntu.com/security/cves/<id>.json) for every open CVE: push when a package's status
    for one of his releases flips to released, with the fix version and each PC's state; close when every PC runs it."""
    oc = seen.setdefault('_open_cves', {})
    for c in FIX_WATCH:
        oc.setdefault(c, {'t': time.time(), 'title': 'from [fixes] watch', 'state': {}, 'miss': 0})
    if not oc:
        return
    pcs = seen.get('_pcs', {})
    codenames = sorted({d.get('codename') for d in pcs.values() if d.get('codename')} or {'noble'})
    now = time.time()
    for cve, info in list(oc.items()):
        if now - info.get('t', now) > 21 * 86400:
            del oc[cve]
            continue
        try:
            r = requests.get(f"https://ubuntu.com/security/cves/{cve}.json", headers=UBUNTU_HEADERS, timeout=8)
            if r.status_code == 404:
                info['miss'] = info.get('miss', 0) + 1
                if info['miss'] >= 3:
                    print(f"[fixes] {cve}: not in Ubuntu's tracker — dropped")
                    del oc[cve]
                continue
            r.raise_for_status()
            d = r.json()
        except Exception as e:
            print(f"[fixes] {cve}: {e}")
            info['miss'] = info.get('miss', 0) + 1                  # a timeout = not triaged yet (404 takes 30-50 s)
            if info['miss'] >= 3:
                print(f"[fixes] {cve}: Ubuntu's tracker never answered — dropped (the Zorin line catches it later)")
                del oc[cve]
            continue
        shipped, all_done = [], True
        for p in d.get('packages', []):
            for st in p.get('statuses', []):
                cn, status = st.get('release_codename'), (st.get('status') or '').lower()
                if cn not in codenames or status in ('dne', 'not-affected', 'ignored', ''):
                    continue
                if p['name'].startswith('linux') and p['name'] not in _kernel_pkgs(pcs, cn):
                    continue                                       # aws/azure/nvidia/raspi kernels are not his
                if not p['name'].startswith('linux') and _installed_src(p['name']) == '':
                    continue                                       # v3.6: a package this PC does not have
                key = f"{p['name']}/{cn}"
                pver = (st.get('description') or '').strip()[:40]
                if status == 'pending' and p['name'].startswith('linux') and _kver(pver) and _kver(_apt_kernel_candidate()) >= _kver(pver):
                    status = 'released'                            # v3.6: apt can install it, whatever the tracker says
                prev = info['state'].get(key, {}).get('status')
                info['state'][key] = {'status': status, 'ver': (st.get('description') or '').strip()[:40]}
                if status == 'released' and prev is not None and prev != 'released':
                    shipped.append((p['name'], cn, info['state'][key]['ver']))
                if status == 'released' and prev is None:
                    info['old'] = True                             # the fix was out before Scout looked
                if status != 'released':
                    all_done = False
        if not info['state'] and d.get('packages'):
            print(f"[fixes] {cve}: none of its packages is installed on this PC — dropped")
            del oc[cve]
            continue
        if info.pop('old', False) and all(v['status'] == 'released' for v in info['state'].values()):
            print(f"[fixes] {cve}: already fixed before the alert — dropped")
            del oc[cve]
            continue
        if shipped:
            lines = [f"{cve} — {d.get('description', '')[:160]}", f"Ubuntu priority: {d.get('priority', '?')}, CVSS {d.get('cvss3', '?')}"]
            for pkg, cn, ver in shipped:
                lines.append(f"* {pkg} on {cn}: fixed in {ver or 'a new version'}")
                lines.extend(_fix_lines_for(cve, pkg, cn, ver, pcs))
            still = [f"{k}: {v['status']}" + (f" ({v['ver']})" if v['ver'] else '') for k, v in info['state'].items() if v['status'] != 'released']
            if still:
                lines.append("Still waiting: " + '; '.join(still))
            alert_all(f"Fix shipped: {cve} (Linux)", lines, severity='warning', routine=False)
            info['shipped_t'] = now
        if all_done and info['state']:
            kernel_fix = [v['ver'] for k, v in info['state'].items() if k.startswith('linux')]
            want = max([_kver(v) for v in kernel_fix] or [()])
            if not want or all(_kver(d.get('kernel', '')) >= want for d in pcs.values()) or now - info.get('shipped_t', now) > 10 * 86400:
                if want and pcs:
                    alert(f"Closed: {cve} — all {len(pcs)} PC(s) run the fixed kernel", 
                          '\n'.join(f"{h}: {d.get('kernel')}" for h, d in sorted(pcs.items())), severity='info')
                del oc[cve]
    print(f"[fixes] {len(oc)} open CVE(s) watched: {', '.join(sorted(oc)) or '-'}")

def fix_status_lines():
    """For the briefs: the open CVEs and where Ubuntu stands with each."""
    oc = _seen().get('_open_cves', {})
    if not oc:
        return []
    out = ["OPEN FIXES (Ubuntu):"]
    for cve, info in sorted(oc.items()):
        parts = [f"{k}: {v['status']}" + (f" {v['ver']}" if v['ver'] else '') for k, v in info.get('state', {}).items()]
        out.append(f"• {cve}: " + ('; '.join(parts) if parts else 'not checked yet'))
    return out[:12]

def check_this_pc(seen):
    """Is THIS machine patched? Security updates waiting (apt), and a reboot still needed to load an installed
    kernel or library fix. Warns once a day when either has waited too long (24 h / 48 h). Read-only."""
    print("[This-PC] checking...")
    try:
        import shutil, subprocess
        osname = ''
        try:
            osname = re.search(r'PRETTY_NAME="?([^"\n]+)', open('/etc/os-release').read()).group(1)
        except (OSError, AttributeError):
            pass
        if shutil.which('apt'):                                   # Debian / Ubuntu / Zorin / Mint
            out = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True, timeout=60).stdout
            sec = sorted({l.split('/')[0] for l in out.splitlines() if '-security' in l})
            fix_cmd = 'sudo apt update && sudo apt upgrade'
        elif shutil.which('dnf'):                                 # RHEL / Rocky / Alma / Fedora (v2.7)
            out = subprocess.run(['dnf', '-q', 'updateinfo', 'list', '--security'], capture_output=True, text=True,
                                 timeout=120).stdout
            sec = sorted({l.split()[-1] for l in out.splitlines() if len(l.split()) >= 3})
            fix_cmd = 'sudo dnf upgrade --security'
        else:
            print("[This-PC] neither apt nor dnf here — skipped")
            return
        now, today = time.time(), datetime.date.today().isoformat()
        if sec:
            seen.setdefault('_pc_sec_since', now)
        else:
            seen.pop('_pc_sec_since', None)
        reboot, rpkgs = os.path.exists('/var/run/reboot-required'), []
        if reboot:
            try:
                rpkgs = open('/var/run/reboot-required.pkgs').read().split()
            except OSError:
                pass
            r_age = now - os.path.getmtime('/var/run/reboot-required')
        _last_health['pc'] = (f"this PC ({osname or 'Linux'}): {len(sec)} security update(s) waiting" +
                              (", reboot needed" if reboot else ''))
        lines = []
        if sec and now - float(seen['_pc_sec_since']) > 24 * 3600:
            lines.append(f"* {len(sec)} security update(s) waiting for over a day: {', '.join(sec[:12])}\n"
                         f"  {fix_cmd}   (are automatic updates running?)")
        if reboot and r_age > 48 * 3600:
            lines.append(f"* Reboot needed for {r_age / 86400:.0f} day(s) — installed fixes are not active yet: "
                         f"{', '.join(sorted(set(rpkgs))[:8]) or 'see /var/run/reboot-required.pkgs'}")
        if lines and seen.get('_pc_warned') != today:
            seen['_pc_warned'] = today
            alert_all("This PC: security patches not applied", lines, severity='warning', routine=False)
        print(f"[This-PC] {len(sec)} security update(s) waiting" + (", reboot needed" if reboot else ''))
        source_ok('This-PC')
    except Exception as e:
        source_error('This-PC', e)

def check_rss(seen, url, source_name, severity='warning', fast=False):
    print(f"[{source_name}] checking...")
    try:
        # v3.2: from the cloud (a datacenter address) a plain 'scout/1.0' is refused by several sites — a browser identity
        h = REDDIT_HEADERS if ('reddit.com' in url or _state.get('cloud')) else HEADERS
        r = cond_get(url, headers=h, timeout=15, retries=1 if fast else 3)
        if r is not None and r.status_code == 304:
            print(f"[{source_name}] unchanged")
            source_ok(source_name)
            return
        if r is not None and r.status_code == 429:
            if fast:
                _demoted[source_name] = datetime.date.today().isoformat()
                print(f"[{source_name}] rate limited — slow lane for the rest of today")
            else:
                print(f"[{source_name}] rate limited")
            return
        if r is None or not r.content:
            raise ConnectionError("no response")
        if r.status_code >= 400:                    # v3.1: a moved feed answered 404 for days and looked "quiet"
            raise ConnectionError(f"HTTP {r.status_code} — the feed moved or is gone")
        root = parse_xml_robust(r.content)
        if root is None:
            raise ValueError("not readable as RSS/Atom (broken XML or an HTML page)")
        ns    = {'atom': 'http://www.w3.org/2005/Atom', 'rss1': 'http://purl.org/rss/1.0/'}
        items = root.findall('.//item') or root.findall('.//atom:entry', ns) or root.findall('.//rss1:item', ns)
        new_items, urgent, rest = [], [], []
        full = source_name in FULL_FEEDS
        priming = full and not seen.get(f'_full_primed_{source_name}')   # first full read: remember, don't flood
        # v3.1: a feed that is new, or whose address changed, is read once quietly — its old items are not news
        url_key = f'_feed_url_{source_name}'
        if seen.get(url_key) != url:
            if url_key in seen or not any(k.startswith(source_name + '_') for k in seen):
                priming = True
                print(f"[{source_name}] new or moved feed — first read only remembers")
            seen[url_key] = url
        for item in items[:30]:
            # v2.2: an element with no children is FALSE in ElementTree, so "find('title') or …" threw away every
            # RSS title and link (the atom fallback is None for RSS) — 40+ feeds matched nothing since v1.4.
            title_el = item.find('title')
            if title_el is None:
                title_el = item.find('atom:title', ns)
            if title_el is None:
                title_el = item.find('rss1:title', ns)              # v2.3: RSS 1.0 (Debian DSA)
            link_el = item.find('link')
            if link_el is None:
                link_el = item.find('atom:link', ns)
            if link_el is None:
                link_el = item.find('rss1:link', ns)
            title = (title_el.text or '').strip() if title_el is not None else ''
            link  = ''
            if link_el is not None:
                link = (link_el.text or link_el.get('href', '')).strip()
            # description / summary — strip HTML, collapse whitespace, cap at 160 chars
            preview, desc_full = '', ''
            for tag in ('description', 'atom:summary', 'atom:content', 'rss1:description'):
                ns_tag = tag if ':' not in tag else None
                el = item.find(tag, ns) if ':' in tag else item.find(tag)
                if el is not None and el.text:
                    desc_full = ' '.join(html.unescape(re.sub(r'<[^>]+>', ' ', el.text)).split())[:1500]
                    preview = desc_full[:160]
                    break
            key = f"{source_name}_{link or title}"
            track_cves(title, source_name)
            if source_name not in NO_CONFIRM:
                mention(f"{title} {desc_full[:500]}", source_name, link, title)
            if key not in seen and full and not matches(title):          # v2.7: the rest of a full feed
                seen[key] = True
                if priming:
                    continue
                mark = '⚠ network-facing — ' if source_name == 'Linux-kernel-CVE' and _KERNEL_NET_RE.search(title) else ''
                rest.append(f"* {mark}{title}" + (f"\n  {preview[:140]}" if preview and preview[:60] not in title else '')
                            + f"\n  {link}")
                continue
            if key not in seen and matches(title):
                seen[key] = True
                if priming:
                    continue
                detail = preview
                if severity == 'critical' or is_urgent(title):          # v2.4: the briefing, from the feed's own text
                    detail = enrich(f"{title}. {desc_full or preview}", source_name)[:900] or preview
                line = f"* {title}\n  {detail}\n  {link}" if detail else f"* {title}\n  {link}"
                if severity != 'critical' and is_urgent(title):
                    urgent.append(line)
                else:
                    new_items.append(line)
        if urgent:                                                   # v2.3: at once, whatever the source's tier
            alert_all(f"{source_name}: {len(urgent)} urgent — your critical gear", urgent, severity='critical')
        if new_items and severity == 'critical':
            alert_all(f"{source_name}: {len(new_items)} item(s)", new_items, severity=severity)
        elif new_items:                                              # v2.3: news goes into the cycle digest
            _cycle_digest.extend(f"[{source_name}] {l}" for l in new_items)
        if rest:
            _cycle_digest.extend(f"[{source_name}] {l}" for l in rest)
        if priming and items:
            seen[f'_full_primed_{source_name}'] = True
        if not new_items and not urgent and not rest:
            print(f"[{source_name}] nothing new")
        source_ok(source_name)
    except Exception as e:
        source_error(source_name, e)

# ── source list ───────────────────────────────────────────────────────────────

RSS_SOURCES = [
    # ── threat research blogs ────────────────────────────────────────────────
    ('https://www.bleepingcomputer.com/feed/',                        'BleepingComputer', 'warning'),
    ('https://feeds.feedburner.com/TheHackersNews',                   'TheHackersNews',   'warning'),
    ('https://www.securityweek.com/feed/',                            'SecurityWeek',     'warning'),
    ('https://isc.sans.edu/rssfeed_full.xml',                         'SANS-ISC',         'warning'),
    ('https://www.rapid7.com/rss.xml',                                'Rapid7',           'warning'),  # v3.4: /blog/rss.xml was 404
    ('https://blog.talosintelligence.com/rss/',                       'Cisco-Talos',      'critical'),
    ('https://unit42.paloaltonetworks.com/feed/',                     'Unit42',           'critical'),
    ('https://www.tenable.com/blog/feed',                             'Tenable',          'warning'),
    # ── exploits / PoC (PacketStorm removed in v3.5: moved to packetstorm.news behind an anti-bot page; Sploitus carries it) ──
    ('https://www.exploit-db.com/rss.xml',                            'Exploit-DB',       'critical'),
    ('https://www.zerodayinitiative.com/rss/published/',              'ZDI',              'critical'),
    # ── advisories ───────────────────────────────────────────────────────────
    ('https://www.cisa.gov/cybersecurity-advisories/all.xml',         'CISA-Alerts',      'critical'),
    ('https://www.cisa.gov/uscert/ics/advisories.xml',                'CISA-ICS',         'critical'),
    ('https://api.msrc.microsoft.com/update-guide/rss',               'MSRC',             'critical'),
    ('https://ccb.belgium.be/advisories.xml',                        'CERT.be',          'warning'),  # v3.3: old path 404 since 26 Oct
    # ── security mailing lists (earliest 0day signal) ───────────────────────
    ('https://seclists.org/rss/oss-sec.rss',          'oss-security',    'critical'),
    ('https://seclists.org/rss/fulldisclosure.rss',   'Full-Disclosure', 'critical'),
    ('https://seclists.org/rss/bugtraq.rss',          'Bugtraq',         'critical'),
    # ── vendor-direct advisories ─────────────────────────────────────────────
    ('https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml', 'Cisco-SA', 'critical'),  # v3.1: old URL 404
    ('https://developer.joomla.org/security-centre.feed?type=rss',       'Joomla-SA', 'critical'),  # v3.3: old path 404 since 26 Oct
    # ── more CERTs / government ──────────────────────────────────────────────
    ('https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml',                                                                    'NCSC-UK',     'critical'),
    ('https://www.jpcert.or.jp/english/rss/jpcert-en.rdf',                                                                               'JPCERT',      'critical'),  # v3.1: old URL 404
    ('https://jvn.jp/en/rss/jvn.rdf',                                                                                                    'JVN',         'warning'),
    ('https://www.cert.ssi.gouv.fr/feed/',                                                                                               'CERT-FR',     'critical'),
    ('https://wid.cert-bund.de/content/public/securityAdvisory/rss',                                                                     'BSI-Germany', 'warning'),   # v3.1: old URL 404; 250 items → digest tier
    # CERT-CC feed is 404 (merged into CISA) — removed
    # ── elite threat research ────────────────────────────────────────────────
    ('https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v',   'Mandiant',         'critical'),  # v3.1: now Google Threat Intelligence
    ('https://research.checkpoint.com/feed/',                         'CheckPoint',       'critical'),
    ('https://securelist.com/feed/',                                  'Securelist',       'warning'),
    ('https://www.crowdstrike.com/en-us/blog/feed/',                  'CrowdStrike',      'warning'),
    # ── container / cloud ────────────────────────────────────────────────────
    ('https://www.aquasec.com/feed/',                                 'AquaSec',          'warning'),  # v3.4: /blog/feed/ was 404
    ('https://www.wiz.io/feed/rss.xml',                               'Wiz',              'warning'),  # v3.4: /blog/feed/rss was 404
    # ── vendor security research ─────────────────────────────────────────────
    ('https://www.welivesecurity.com/feed/',                          'ESET',             'warning'),
    ('https://www.sophos.com/en-us/category/threat-research/feed',    'Sophos',           'warning'),  # v3.4: X-Ops threat research; old path 404
    ('https://vulners.com/rss.xml',                                   'Vulners',          'warning'),
    ('https://feeds.feedburner.com/TrendMicroSimplySecurity',         'TrendMicro',       'warning'),  # v3.4: research rss.xml was 404
    # ── vendor patch advisories (direct from distros) ────────────────────────
    ('https://access.redhat.com/security/security-updates/advisory/rss', 'RedHat-SA',    'critical'),
    ('https://ubuntu.com/security/notices/rss.xml',                   'Ubuntu-USN',       'critical'),
    # ── mass exploitation early warning (ShadowServer removed in v3.4: no feed exists any more) ──────────────────
    ('https://www.greynoise.io/blog/rss.xml',                          'GreyNoise',       'critical'),  # v3.4: /blog/rss was 404
    # ── community ────────────────────────────────────────────────────────────
    ('https://www.reddit.com/r/netsec/.rss',                          'Reddit-netsec',    'info'),
    ('https://www.reddit.com/r/cybersecurity/.rss',                   'Reddit-cybersec',  'info'),
    # ── v2.3 "eyes and ears" for work: vendor PSIRTs, CERTs, release channels (each verified before adding) ──
    ('https://security.paloaltonetworks.com/rss.xml',                 'PaloAlto-SA',      'critical'),
    ('https://filestore.fortinet.com/fortiguard/rss/ir.xml',          'Fortinet-PSIRT',   'critical'),
    ('https://cert.europa.eu/publications/security-advisories-rss',   'CERT-EU',          'critical'),
    ('https://www.debian.org/security/dsa',                           'Debian-DSA',       'critical'),
    ('https://advisories.ncsc.nl/rss/advisories',                     'NCSC-NL',          'warning'),
    ('https://www.jenkins.io/security/advisories/rss.xml',            'Jenkins-SA',       'warning'),
    ('https://about.gitlab.com/security-releases.xml',                'GitLab-SR',        'warning'),
    ('https://chromereleases.googleblog.com/feeds/posts/default',     'Chrome-Releases',  'warning'),
    ('https://www.microsoft.com/en-us/security/blog/feed/',           'MS-Security-Blog', 'warning'),
    ('https://googleprojectzero.blogspot.com/feeds/posts/default',    'Project-Zero',     'warning'),
    ('https://www.huntress.com/blog/rss.xml',                         'Huntress',         'warning'),
    # ── v2.7: Linux servers beyond Ubuntu — RHEL family (with severity), older Debian, the kernel's CVE list ──
    ('https://errata.almalinux.org/9/errata.rss',                     'AlmaLinux',        'warning'),
    ('https://www.debian.org/lts/security/dla',                       'Debian-DLA',       'warning'),
    ('https://lore.kernel.org/linux-cve-announce/new.atom',           'Linux-kernel-CVE', 'warning'),
]

# ── v2.8 (S3): Claude as the analyst — morning brief, weekly letter, Patch Tuesday ───────────────────────────
BRIEF_HOUR   = int(cfg.get('brief', 'morning_hour', fallback='7') or 7)
WEEKLY_DAY   = int(cfg.get('brief', 'weekly_weekday', fallback='6') or 6)     # 0 = Monday … 6 = Sunday
WEEKLY_HOUR  = int(cfg.get('brief', 'weekly_hour', fallback='19') or 19)
EVENING_HOUR = int(cfg.get('brief', 'evening_hour', fallback='18') or 0)     # v3.6: second daily brief; 0 = off
BRIEF_MODEL  = cfg.get('brief', 'model', fallback='').strip() or ANTHROPIC_MODEL

_ANALYST = (
    "You are the security analyst for a system engineer. He runs, at work and at home, among others: "
    f"{', '.join(_CRITICAL_NAMES)}; and he cares about: {', '.join(_PRODUCT_NAMES)}. You get the items his own "
    "monitoring sent him (urgent alerts and digests), each with its time and priority. Use ONLY these items: never "
    "invent CVE ids, versions, dates or facts; merge the items that are one story; say 'not stated' when something "
    "is missing. Plain text for a phone screen: no markdown headers, no tables, no bold.")

_BRIEF_SHAPE = (
    "Write his morning brief in this shape:\n"
    "PATCH TODAY — numbered, in the order to do it. Each: product and CVE(s) → why now → what to do. Only items "
    "that hit his products; at most 7; 'nothing urgent' if none. Order: exploited in the wild or in CISA KEV first, "
    "then public exploit or PoC, then internet-facing (VPN, firewall, mail, web, RDP, remote access), then severity.\n"
    "THIS WEEK — numbered, his products, serious but no sign of exploitation yet; at most 7.\n"
    "WATCH — short lines: stories still developing, or maybe his but not confirmed.\n"
    "NOISE — one line: what you left out and why (for example '18 WordPress plugin CVEs, 6 vendor blog posts').\n"
    "At most 380 words.")

_EVENING_SHAPE = (
    "Write his evening brief — what changed since this morning, readable in a minute:\n"
    "NEW TODAY — numbered, his products only: product and CVE(s) → why it matters → what to do tonight or tomorrow; "
    "at most 6; 'nothing new for your stack' if none.\n"
    "STILL OPEN — items waiting for a vendor fix (for example a kernel CVE where Ubuntu has not shipped yet): one "
    "line each with the current status as stated in the items.\n"
    "WATCH — short lines: stories still developing.\n"
    "NOISE — one line: what you left out.\nAt most 300 words.")

def evening_brief(seen, now=None):
    """v3.6: the second daily report, the first check after evening_hour: the last 12 hours. Skipped on the weekly
    letter's day (the letter covers it). Without AI (no key, no credit) the plain list goes out instead."""
    now = now or datetime.datetime.now()
    today = now.strftime('%Y-%m-%d')
    if not EVENING_HOUR or now.hour < EVENING_HOUR or seen.get('_evening_day') == today:
        return
    seen['_evening_day'] = today
    if now.weekday() == WEEKLY_DAY:
        return
    _send_ai_report(seen, f"Evening brief {now.strftime('%a %d %b')}", journal_read(12), _EVENING_SHAPE,
                    'evening brief', 60000, footer=fix_status_lines())

_WEEKLY_SHAPE = (
    "Write his weekly letter, readable in two minutes:\n"
    "EXPLOITED THIS WEEK — what was attacked in the wild that touches his products, with the day it surfaced.\n"
    "PATCH CHECKLIST — numbered, everything of his that got a security fix this week, most urgent first, so he can "
    "tick off what he has done.\n"
    "TRENDS — 2 to 4 lines: which vendors, attack types or actors kept coming back.\n"
    "NEXT WEEK — what to keep an eye on (pending patches, Patch Tuesday, developing stories).\n"
    "At most 450 words.")

def _journal_digest(entries, limit_chars):
    """The journal for the model: urgent first, then newest, duplicates dropped, within limit_chars."""
    rank = {'critical': 0, 'warning': 1, 'info': 2}
    out, seen_txt, size = [], set(), 0
    for e in sorted(entries, key=lambda e: (rank.get(e.get('sev'), 3), -e.get('t', 0))):
        text = ' '.join(e.get('text', '').split())
        sig = text[:120]
        if sig in seen_txt:
            continue
        seen_txt.add(sig)
        line = (f"[{datetime.datetime.fromtimestamp(e.get('t', 0)).strftime('%a %H:%M')}] ({e.get('sev')}) "
                f"{e.get('title', '')}: {text[:500]}")
        if size + len(line) > limit_chars:
            break
        out.append(line)
        size += len(line)
    return out

def _fallback_brief(entries, what):
    """No AI (no key, no credit, no network): the brief still comes — the urgent items, deduplicated."""
    crit = _journal_digest([e for e in entries if e.get('sev') == 'critical'], 6000)
    counts = {s: sum(1 for e in entries if e.get('sev') == s) for s in ('critical', 'warning', 'info')}
    lines = [f"(AI not available{': ' + _ai_state['reason'] if _ai_state.get('reason') else ''} — {what} without it)",
             f"{counts['critical']} urgent, {counts['warning']} normal, {counts['info']} low items."]
    lines += [f"• {c.split(': ', 1)[-1].lstrip('* ')[:230]}" for c in crit[:12]] or ["• nothing urgent"]
    return lines

def _send_ai_report(seen, title, entries, shape, what, max_chars, footer=None):
    pending = [{'t': time.time(), 'sev': 'warning', 'title': 'not yet sent (digest)', 'text': d}
               for d in _cycle_digest]                       # news waiting for the next slow cycle counts too
    allitems = entries + pending
    if not allitems:
        print(f"[{what}] nothing in the journal — skipped")
        return
    items = _journal_digest(allitems, max_chars)
    text = ai_call(_ANALYST, f"{shape}\n\n{len(items)} items:\n" + '\n'.join(items),
                   max_tokens=8000, effort='medium', model=BRIEF_MODEL, timeout=180.0)
    lines = [l for l in text.splitlines() if l.strip()] if text else _fallback_brief(allitems, what)
    lines.extend(footer or [])
    lines.append(f"— {len(allitems)} items read" + (f" by {BRIEF_MODEL}" if text else ''))
    alert_all(title, lines, severity='warning', journal=False, routine=False)

def morning_brief(seen, now=None):
    """Once a day, the first check after morning_hour: the last 24 hours in one message — patch today, this week,
    watch, noise. A PC that was off at 07:00 sends it at the first check after boot."""
    now = now or datetime.datetime.now()
    today = now.strftime('%Y-%m-%d')
    if '_brief_day' not in seen:                     # first start of v2.8: the journal is empty, begin tomorrow
        seen['_brief_day'] = today
    if now.hour < BRIEF_HOUR or seen.get('_brief_day') == today:
        return
    seen['_brief_day'] = today
    journal_prune()
    _send_ai_report(seen, f"Morning brief {now.strftime('%a %d %b')}", journal_read(24), _BRIEF_SHAPE,
                    'morning brief', 60000, footer=fix_status_lines())

def weekly_letter(seen, now=None):
    now = now or datetime.datetime.now()
    week = now.strftime('%G-W%V')
    if '_weekly_key' not in seen:
        seen['_weekly_key'] = week
    if now.weekday() != WEEKLY_DAY or now.hour < WEEKLY_HOUR or seen.get('_weekly_key') == week:
        return
    seen['_weekly_key'] = week
    _send_ai_report(seen, f"Weekly letter {week}", journal_read(7 * 24), _WEEKLY_SHAPE, 'weekly letter', 90000,
                    footer=push_stats())

_PATCH_TUESDAY_SHAPE = (
    "This is Microsoft's monthly security release. Tell him what to patch first on his Windows Servers, Exchange, "
    "SQL Server, Hyper-V and clients. Shape:\n"
    "FIRST — numbered, at most 6: exploited or publicly disclosed, then wormable/unauthenticated network RCE on "
    "server roles (DNS, Kerberos/KDC, RDP, RRAS, SMB, Hyper-V, Exchange), each with why.\n"
    "THEN — one or two lines of what follows.\n"
    "CAN WAIT — one line.\nAt most 220 words.")

_DIGEST_SHAPE = (
    "Below is everything his monitoring collected in the last hours that was not urgent enough for an instant push, "
    "grouped by source. Explain it for his phone, so he knows in 30 seconds whether to act:\n"
    "WHAT MATTERS — 1 to 6 numbered lines: the items worth his attention (his products, fixes to schedule, "
    "exploitation news, anything internet-facing), each: what → why it matters → what to do.\n"
    "BY SOURCE — one short line per group: what it is about this time and whether anything needs action, e.g. "
    "'Ubuntu-USN (3): routine package fixes (poppler, Ghostscript, U-Boot) — normal updates, nothing urgent'.\n"
    "BOTTOM LINE — one sentence (it may honestly be 'nothing to do').\nAt most 320 words.")

def explain_digest(groups):
    """The top of the 6-hour report: Claude's explanation, or — without AI — a plain overview per source."""
    items = []
    for src, bodies in groups.items():
        for b in bodies:
            items.append(f"[{src}] {' '.join(b.split())[:400]}")
    text = None
    if items:
        text = ai_call(_ANALYST, f"{_DIGEST_SHAPE}\n\n{len(items)} items:\n" + '\n'.join(items)[:45000],
                       max_tokens=6000, effort='medium', model=BRIEF_MODEL, timeout=180.0)
    if text:
        return [l for l in text.splitlines() if l.strip()]
    out = ["OVERVIEW (no AI right now)"]
    for src in sorted(groups, key=lambda g: -len(groups[g])):
        heads = [re.sub(r'^\*\s*', '', b.split('\n')[0])[:70] for b in groups[src][:3]]
        out.append(f"• {src} ({len(groups[src])}): " + '; '.join(heads) + (' …' if len(groups[src]) > 3 else ''))
    return out

TOTAL_SOURCES = 23 + len(RSS_SOURCES)          # 16 API checks + Google News, Telegram, Synology, MikroTik, MSRC-CVRF, This-PC
_last_health = {'ok': TOTAL_SOURCES, 'total': TOTAL_SOURCES, 'pc': ''}

def _parked_now(name):
    return _seen().get('_parked', {}).get(name, 0) > time.time()

def _fast_rss():
    today = datetime.date.today().isoformat()
    return [s for s in RSS_SOURCES if s[1] in FAST_RSS and _demoted.get(s[1]) != today and not _parked_now(s[1])]

def run_fast(seen):
    """The fast lane: the earliest, cheapest sources. Urgent items and PoCs go out at once; news waits for the
    digest of the next slow cycle."""
    t0 = time.time()
    check_cisa_kev(seen)
    check_hackernews_algolia(seen)
    check_mastodon(seen)
    check_github_pocs(seen)
    check_poc_in_github(seen)
    check_google_news(seen)
    check_telegram(seen)
    check_msrc(seen)
    for url, name, sev in _fast_rss():
        check_rss(seen, url, name, severity=sev, fast=True)
    _prune_mentions()
    save_seen(seen)
    print(f"[Scout] fast lane done in {time.time() - t0:.0f}s — {8 + len(_fast_rss())} sources")

def run_slow(seen):
    """The slow lane: everything not in the fast lane (plus fast feeds demoted today), then the digest of all news
    since the last slow cycle, the trending CVEs, the failures and the daily line."""
    global _cycle_errors, _cycle_cve_hits, _cycle_digest
    fast_now = {s[1] for s in _fast_rss()}
    check_nvd(seen)
    check_nvd_modified(seen)
    check_nvd_high(seen)
    check_mitre_cve(seen)
    check_circl(seen)
    check_osv(seen)
    check_github_advisories(seen)
    check_nuclei_templates(seen)
    check_vulhub(seen)
    check_product_releases(seen)
    check_sploitus(seen)
    check_synology(seen)
    check_mikrotik(seen)
    if not _state.get('cloud'):                     # the runner's own apt state means nothing to you
        check_this_pc(seen)
    check_pcs(seen)                                 # v3.6: the fleet from the PC topic (works from the cloud too)
    track_fixes(seen)
    check_kernel_releases(seen)
    for url, name, sev in RSS_SOURCES:
        if name not in fast_now and not _parked_now(name):
            check_rss(seen, url, name, severity=sev)
    save_seen(seen)
    if _cycle_digest:                                       # v2.3: the news since the last slow cycle, one notification
        shown = seen.get('_topic_links', {})
        kept = [e for e in _cycle_digest if not (_URL_RE.search(e) and _URL_RE.search(e).group(0).rstrip(').,;') in shown)]
        if len(kept) < len(_cycle_digest):                  # v3.3: the cloud's report already carried these
            print(f"[digest] {len(_cycle_digest) - len(kept)} item(s) already shown in a report on the topic — left out")
        _cycle_digest[:] = kept
    left_out = 0
    if _cycle_digest and _REPORT_RE:                        # v3.6: [report] only — his gear, the rest one footer line
        kept = [e for e in _cycle_digest if _REPORT_RE.search(e.lower())]
        left_out = len(_cycle_digest) - len(kept)
        if left_out:
            print(f"[digest] {left_out} item(s) about other products left out of the report ([report] only)")
        _cycle_digest[:] = kept
    if _cycle_digest:
        groups = {}
        for entry in _cycle_digest:                         # v2.7: grouped by source, so 100 items stay readable
            m = re.match(r'\[([^\]]+)\] (.*)', entry, re.S)
            src, body = (m.group(1), m.group(2)) if m else ('Other', entry)
            groups.setdefault(src, []).append(body)
        lines = []
        for src in sorted(groups, key=lambda g: -len(groups[g])):
            lines.append(f"── {src} ({len(groups[src])}) ──")
            lines.extend(groups[src])
        explained = explain_digest(groups)                  # v3.1: Claude says what matters, then the full list
        if left_out:
            lines.append(f"── {left_out} item(s) about other products left out ([report] only in scout.conf) ──")
        alert_all(f"Scout {INTERVAL} h report: {len(_cycle_digest)} item(s)",
                  explained + ['', '═══ every item ═══'] + lines, severity='warning', routine=False)

    ts = datetime.datetime.now().strftime('%H:%M:%S')
    failed = len(_cycle_errors)
    ok = TOTAL_SOURCES - failed
    _last_health.update(ok=ok, total=TOTAL_SOURCES)
    print(f"[Scout] slow cycle done {ts} — {ok}/{TOTAL_SOURCES} sources OK, {failed} failed")

    # CVE correlation — same CVE mentioned by 2+ independent sources = confirmed signal
    trending = {
        cve: srcs for cve, srcs in _cycle_cve_hits.items()
        if len(srcs) >= 2
    }
    if trending:                                    # v3.6: only the ones about his products are pushed; the rest = report
        mine = {c: s_ for c, s_ in trending.items() if _cycle_cve_prods.get(c)}
        others = len(trending) - len(mine)
        if mine:
            ranked = sorted(mine.items(), key=lambda x: -len(x[1]))
            lines = [f"• {cve} ({', '.join(_cycle_cve_prods[cve][:2])}) × {len(srcs)} sources: {', '.join(srcs)}" for cve, srcs in ranked[:6]]
            if others:
                lines.append(f"+ {others} trending CVE(s) about other products, not pushed")
            alert(f"Trending CVEs: {len(mine)} about your gear", "\n".join(lines), severity='warning')
        else:
            print(f"[trending] {len(trending)} CVE(s) seen by 2+ sources, none about his products — no push")
        _cycle_digest.append("[Trending] " + ', '.join(f"{c} ×{len(s_)}" for c, s_ in sorted(trending.items(), key=lambda x: -len(x[1]))[:25]))

    refused = {n: v for n, v in _cycle_errors.items()
               if _state.get('cloud') and v[1].startswith('ConnectionError: HTTP 40')}   # v3.5: GitHub's addresses
    real = {n: v for n, v in _cycle_errors.items() if n not in refused}
    failed = len(real)
    ok = TOTAL_SOURCES - failed
    _last_health.update(ok=ok)
    if real:
        lines = [f"• {n}" + (f" (×{c})" if c > 1 else '') + f": {m}" for n, (c, m) in real.items()]
        if refused:
            lines.append("Only readable from home (refused from GitHub's addresses): " + ', '.join(sorted(refused)))
        if _cycle_recovered:
            lines.append("Brief errors that recovered by themselves: " +
                         ', '.join(f"{n} ×{c}" for n, c in sorted(_cycle_recovered.items())))
        alert(f"Scout: {failed} source(s) failed in the last {INTERVAL} h", "\n".join(lines), severity='warning')
    elif refused or _cycle_recovered:
        print(f"[Scout] no source failing at the end of the cycle (refused from the cloud: {len(refused)}, "
              f"recovered blips: {sum(_cycle_recovered.values())})")

    _cycle_errors   = {}
    _cycle_cve_hits = {}
    _cycle_cve_prods.clear()
    _cycle_digest   = []
    _cycle_recovered.clear()
    _ai_state['used'] = 0
    _ai_state['told'] = False

def daily_heartbeat(seen, ok, total, now=None):
    """v2.2: once a day (first cycle after 07:00) a low-priority line that the scout is alive and how many
    sources answered — so a quiet phone means "nothing happened", not "the scout died"."""
    now = now or datetime.datetime.now()
    today = now.strftime('%Y-%m-%d')
    if now.hour < 7 or seen.get('_daily_sent') == today:
        return
    seen['_daily_sent'] = today
    alert("Scout daily: alive", f"{ok}/{total} sources answered the last slow cycle; fast lane every {FAST_MINUTES} min, "
          f"everything every {INTERVAL} h; {len(seen)} items remembered; "
          f"{len([t for t in seen.get('_starts', []) if time.time() - t < 7 * 86400])} start(s) in 7 days."
          + (f" {_last_health['pc'].capitalize()}." if _last_health.get('pc') else ''), severity='info')

# ── v3.2: home and cloud share one truth — the ntfy topic ──────────────────────────────────────────────────────
_AGGREGATE_TITLES = ('report', 'digest', 'Morning brief', 'Weekly letter', 'Patch Tuesday', 'Scout daily', 'Scout Online',
                     'Scout watch', 'took over', 'is back', 'internet was down', 'back after a gap')

def sync_from_topic(seen):
    """At start (home) and at every run (cloud): what the topic carried in the last 12 h counts as pushed here too —
    the CVEs and links of routine alerts (one story, one alert), today's morning brief, this week's letter, today's
    daily line. So a handover between the home Scout and the cloud copy repeats nothing."""
    try:
        r = requests.get(f"{NTFY_SERVER}/{NTFY_TOPIC}/json",
                         params={'poll': '1', 'since': int(time.time() - 12 * 3600)}, timeout=15)
        r.raise_for_status()
    except Exception as e:
        print(f"[sync] topic not read: {e}")
        return
    pushed = seen.setdefault('_pushed_cves', {})
    plinks = seen.setdefault('_pushed_links', {})
    tlinks = seen.setdefault('_topic_links', {})           # v3.3: every link shown on the topic, reports included
    for l in [l for l, t in tlinks.items() if time.time() - t > 12 * 3600]:
        del tlinks[l]
    today = datetime.date.today().isoformat()
    week = datetime.datetime.now().strftime('%G-W%V')
    n = 0
    for raw in r.text.splitlines():
        try:
            ev = json.loads(raw)
        except ValueError:
            continue
        if ev.get('event') != 'message':
            continue
        n += 1
        t = float(ev.get('time') or time.time())
        title = (ev.get('title') or '').replace('☁ ', '')
        msg = ev.get('message') or ''
        day = datetime.date.fromtimestamp(t).isoformat()
        if 'Morning brief' in title and day == today:
            seen['_brief_day'] = today
        if 'Weekly letter' in title and datetime.datetime.fromtimestamp(t).strftime('%G-W%V') == week:
            seen['_weekly_key'] = week
        if 'Scout daily: alive' in title and day == today:
            seen['_daily_sent'] = today
        for l in _URL_RE.findall(msg):
            tlinks[l.rstrip(').,;')] = t
        if any(a in title for a in _AGGREGATE_TITLES):
            continue                                       # a digest line is not "already pushed as an alert"
        src = title.split(':')[0][:40]
        for c in {c.upper() for c in CVE_RE.findall(title + ' ' + msg)}:
            pushed.setdefault(c, [t, src])
        for l in _URL_RE.findall(msg):
            plinks.setdefault(l.rstrip(').,;'), t)
    print(f"[sync] {n} message(s) of the last 12 h on the topic taken into account")

def home_alive(minutes=45):
    """Cloud mode: did the home Scout post 'alive' in the last `minutes`? None when ntfy cannot be read."""
    try:
        r = requests.get(f"{NTFY_SERVER}/{hb_topic()}/json",
                         params={'poll': '1', 'since': int(time.time() - 12 * 3600)}, timeout=15)
        r.raise_for_status()
    except Exception as e:
        print(f"[cloud] heartbeat topic not read: {e}")
        return None
    beats = []
    for raw in r.text.splitlines():
        try:
            ev = json.loads(raw)
        except ValueError:
            continue
        if ev.get('event') == 'message':
            beats.append(float(ev.get('time') or 0))
    if beats:
        _seen()['_home_last_beat'] = max(beats)
    return bool(beats) and time.time() - max(beats) < minutes * 60

# What a cloud run must remember until the next one (a new runner every 30 min): kept inside seen.json.
_CLOUD_GLOBALS = ('_demoted', '_validators', '_cycle_errors', '_fail_counts', '_cycle_cve_hits', '_cycle_digest',
                  '_mentions_seen', '_cve_window')

def cloud_state_load(seen):
    g = globals()
    for name in _CLOUD_GLOBALS:
        v = seen.get('_cloud' + name)
        if v is None:
            continue
        if isinstance(g[name], dict):
            g[name].clear()
            g[name].update(v)
        else:
            g[name][:] = v
    _ai_state['used'] = int(seen.get('_cloud_ai_used', 0))

def cloud_state_save(seen):
    for name in _CLOUD_GLOBALS:
        seen['_cloud' + name] = globals()[name]
    seen['_cloud_ai_used'] = _ai_state['used']

def cloud_main():
    """One run of the cloud copy (GitHub Actions, every 30 min). Home alive in the last 45 min → QUIET: read every
    source, remember, journal, push nothing — its memory stays in step with home. Home silent → the full Scout, with
    ☁ in every title, until home reports alive again."""
    _state['cloud'] = True
    seen = load_seen()
    _state['seen'] = seen
    cloud_state_load(seen)
    alive = home_alive()
    if alive is None:                                     # ntfy unreachable from here: never take over blindly
        alive = True
    _state['quiet'] = alive
    was_active = bool(seen.get('_cloud_active'))
    sync_from_topic(seen)
    if not alive and not was_active:
        seen['_cloud_active'] = True
        last = seen.get('_home_last_beat')
        since = datetime.datetime.fromtimestamp(last).strftime('%a %H:%M') if last else 'over 12 h ago'
        alert("Home Scout offline — cloud Scout took over",
              f"No sign of life from the home Scout since {since} (PC off, power cut, no internet or a crash).\n"
              f"Until it is back, this cloud copy runs the full Scout every 30 min: all {TOTAL_SOURCES} sources, "
              f"Confirmed, mutes and buttons, AI briefings, the morning brief. Its pushes carry ☁.\n"
              f"Not possible from here: the patch state of your own PC.", severity='info')
    elif alive and was_active:
        seen['_cloud_active'] = False
        _state['quiet'] = False                           # say it once, then go quiet
        alert("Home Scout is back — cloud quiet again",
              "The home Scout reports alive. The cloud copy keeps reading quietly and takes over again if home goes "
              "silent for 45 min.", severity='info')
        _state['quiet'] = True
    if not online():
        print("[cloud] no network on the runner — nothing done")
        cloud_state_save(seen); save_seen(seen)
        return
    _state['primed'] = bool(seen.get('_cloud_primed'))   # first ever run only fills the Confirmed window
    if not _state['quiet']:
        flush_outbox()
    poll_control(seen)
    run_fast(seen)
    slow_every = INTERVAL if not _state['quiet'] else max(INTERVAL, 12)   # quiet: 12 h is enough to stay in step
    if time.time() - float(seen.get('_last_slow_ts', 0)) >= slow_every * 3600 - 120:
        run_slow(seen)
        seen['_last_slow_ts'] = time.time()
    seen['_cloud_primed'] = True
    if not _state['quiet']:                               # home does these itself while it is alive
        daily_heartbeat(seen, _last_health['ok'], _last_health['total'])
        morning_brief(seen)
        evening_brief(seen)
        weekly_letter(seen)
    cloud_state_save(seen)
    save_seen(seen)
    print(f"[cloud] done — {'QUIET (home alive)' if _state['quiet'] else 'ACTIVE (home offline)'}, "
          f"{len(seen)} keys remembered")

if __name__ == '__main__':
    if '--cloud' in sys.argv or os.environ.get('SCOUT_CLOUD'):
        print(f"Scout v{VERSION} cloud run...")
        cloud_main()
        raise SystemExit(0)
    print(f"Scout v{VERSION} starting...")
    ai_status = f"AI briefings ON ({ANTHROPIC_MODEL}, max {AI_MAX_PER_CYCLE} per {INTERVAL} h)" if ANTHROPIC_KEY \
        else "AI briefings OFF (essentials only)"
    unknown = FAST_RSS - {s[1] for s in RSS_SOURCES}
    if unknown:
        print(f"[lanes] fast_rss names not in the source list (ignored): {', '.join(sorted(unknown))}")
    alert("Scout Online", f"Scout v{VERSION} — {TOTAL_SOURCES} sources: {8 + len(_fast_rss())} every {FAST_MINUTES} min, "
          f"all every {INTERVAL} h. Confirmed-within-the-hour on. Morning brief {BRIEF_HOUR:02d}:00. {ai_status}.", severity='info')
    seen = load_seen()
    _state['seen'] = seen
    import signal, threading
    signal.signal(signal.SIGTERM, _on_stop)
    threading.Thread(target=_watchdog, daemon=True, name='watchdog').start()
    start_report(seen)
    sync_from_topic(seen)                          # v3.2: what the cloud copy pushed meanwhile is not news
    heartbeat('started')
    while True:
        started = time.time()
        _progress['ts'] = started
        if not online():                             # v2.9: no internet — wait, count no failures
            seen.setdefault('_offline_since', time.time())
            heartbeat('offline', offline_since=seen['_offline_since'])
            print("[Scout] offline (no DNS) — next try in 5 min, no source counted as failed")
            time.sleep(300)
            continue
        if '_offline_since' in seen:
            gone = time.time() - seen.pop('_offline_since')
            print(f"[Scout] back online after {gone / 60:.0f} min")
            if gone > 30 * 60:
                alert("Scout: internet was down", f"No internet for {gone / 60:.0f} min "
                      f"(since {datetime.datetime.fromtimestamp(time.time() - gone).strftime('%H:%M')}). "
                      "The lanes are reading what was missed now.", severity='info')
        flush_outbox()                               # v3.1: pushes that failed earlier go first
        poll_control(seen)
        run_fast(seen)
        heartbeat('fast')
        cloud_heartbeat()
        if time.time() - float(seen.get('_last_slow_ts', 0)) >= INTERVAL * 3600 - 120:
            run_slow(seen)
            seen['_last_slow_ts'] = time.time()
            save_seen(seen)
            heartbeat('slow')
        else:
            nxt = datetime.datetime.fromtimestamp(float(seen['_last_slow_ts']) + INTERVAL * 3600).strftime('%H:%M')
            print(f"[Scout] slow lane next at about {nxt}")
        _state['primed'] = True                     # from now on, a second source within the hour is "confirmed"
        daily_heartbeat(seen, _last_health['ok'], _last_health['total'])
        morning_brief(seen)
        evening_brief(seen)
        weekly_letter(seen)
        save_seen(seen)
        wait = max(60, FAST_MINUTES * 60 - (time.time() - started))
        print(f"[Scout] next fast check in {wait / 60:.0f} min")
        time.sleep(wait)
