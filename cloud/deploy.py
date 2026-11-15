#!/usr/bin/env python3
"""Deploy Scout to the private GitHub repo that runs the cloud copy.

  python3 cloud/deploy.py template            write cloud/scout.cloud.conf from the home scout.conf (no secrets)
  python3 cloud/deploy.py push [--with-ai-key] [--run]
        upload scout.py + cloud files + workflow, remove superseded files, set the secrets, optionally start a run
        --with-ai-key   also store the Anthropic key from the home scout.conf as the ANTHROPIC_API_KEY secret
        --run           start one run after deploying and print its log lines

The token (classic, scopes repo + workflow) is read from data/github_setup_token or $GITHUB_DEPLOY_TOKEN.
"""
import base64, configparser, io, json, os, re, sys, time, urllib.error, urllib.request, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REPO = os.environ.get('SCOUT_CLOUD_REPO', 'scout-cloud')
OWNER = os.environ.get('SCOUT_CLOUD_OWNER', '')     # empty = the account the deploy token belongs to (set in push)
HOME_CONF = os.path.join(ROOT, 'data', 'scout.conf')
TEMPLATE = os.path.join(HERE, 'scout.cloud.conf')
CLOUD_MODEL = 'claude-sonnet-5-5'               # v3.6: user's choice for the cloud copy (home stays on Opus)
FILES = {                                   # repo path -> local path
    'scout.py': os.path.join(ROOT, 'scout.py'),
    'cloud/make_conf.py': os.path.join(HERE, 'make_conf.py'),
    'cloud/requirements.txt': os.path.join(HERE, 'requirements.txt'),
    'cloud/scout.cloud.conf': TEMPLATE,
    'cloud/deploy.py': os.path.join(HERE, 'deploy.py'),
    '.github/workflows/scout-cloud.yml': os.path.join(HERE, '.github', 'workflows', 'scout-cloud.yml'),
    '.gitignore': os.path.join(HERE, 'gitignore'),
    'README.md': os.path.join(HERE, 'README.md'),
}
SUPERSEDED = ('scout_cloud.py', 'critical.txt', 'rules.json', 'build_rules.py')


def build_template():
    """The home conf with the secrets replaced by ${VARS} the workflow fills in, and the paths made cloud paths."""
    text = open(HOME_CONF, encoding='utf-8').read()
    text = re.sub(r'(?m)^topic\s*=.*$', 'topic = ${NTFY_TOPIC}', text, count=1)
    if not re.search(r'(?m)^control_topic\s*=', text):
        text = text.replace('topic = ${NTFY_TOPIC}', 'topic = ${NTFY_TOPIC}\ncontrol_topic = ${NTFY_CTL_TOPIC}', 1)
    else:
        text = re.sub(r'(?m)^control_topic\s*=.*$', 'control_topic = ${NTFY_CTL_TOPIC}', text)
    text = re.sub(r'(?m)^seen_db\s*=.*$', 'seen_db = ${WORKSPACE}/data/seen.json', text)
    text = re.sub(r'(?m)^api_key\s*=.*$', 'api_key = ${ANTHROPIC_API_KEY}', text)
    text = re.sub(r'(?m)^token\s*=.*$', 'token = ${GH_PAT}', text)
    text = re.sub(r'(?m)^model\s*=\s*claude-\S+$', f'model = {CLOUD_MODEL}', text, count=1)   # the cloud runs a cheaper model
    header = ("; Cloud copy of scout.conf — built by cloud/deploy.py from the home scout.conf. No secrets here:\n"
              "; ${…} are filled in from GitHub Actions secrets by cloud/make_conf.py at run time.\n")
    with open(TEMPLATE, 'w', encoding='utf-8') as f:
        f.write(header + text)
    for leak in ('sk-ant-', 'ghp_', 'github_pat_'):
        assert leak not in text, f"a secret ({leak}…) is still in the template"
    print(f"template written: {TEMPLATE}")


def token():
    path = os.path.join(ROOT, 'data', 'github_setup_token')
    t = os.environ.get('GITHUB_DEPLOY_TOKEN', '').strip()
    if not t and os.path.exists(path):
        t = open(path).read().strip()
    if not t:
        sys.exit("no token: put it in data/github_setup_token (chmod 600) or $GITHUB_DEPLOY_TOKEN")
    return t


def api(tok, method, path, body=None, raw=False):
    req = urllib.request.Request('https://api.github.com' + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={'Authorization': 'Bearer ' + tok, 'Accept': 'application/vnd.github+json',
                                          'User-Agent': 'scout-deploy', 'X-GitHub-Api-Version': '2022-11-28'})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            d = r.read()
            return r.status, (d if raw else (json.loads(d) if d else {}))
    except urllib.error.HTTPError as e:
        d = e.read()
        return e.code, (d if raw else (json.loads(d or b'{}')))


def put_secret(tok, name, value):
    from nacl import encoding, public
    st, key = api(tok, 'GET', f'/repos/{OWNER}/{REPO}/actions/secrets/public-key')
    box = public.SealedBox(public.PublicKey(key['key'].encode(), encoding.Base64Encoder()))
    enc = base64.b64encode(box.encrypt(value.encode())).decode()
    st, _ = api(tok, 'PUT', f'/repos/{OWNER}/{REPO}/actions/secrets/{name}',
                {'encrypted_value': enc, 'key_id': key['key_id']})
    print(f"secret {name}: {'ok' if st in (201, 204) else st}")


def push(with_ai_key=False, run=False):
    build_template()
    tok = token()
    cfg = configparser.ConfigParser()
    cfg.read(HOME_CONF)
    seen = json.load(open(cfg['scout']['seen_db']))
    ctl = cfg.get('ntfy', 'control_topic', fallback='').strip() or seen.get('_ctl_topic', '')
    if not ctl:
        sys.exit("no control topic yet: start the home Scout once (it creates one), then deploy")
    global OWNER
    if not OWNER:
        st, me = api(tok, 'GET', '/user')
        if st != 200 or not me.get('login'):
            sys.exit(f"the deploy token was refused by GitHub (HTTP {st})")
        OWNER = me['login']
    st, r = api(tok, 'GET', f'/repos/{OWNER}/{REPO}')
    if st == 404:
        st, r = api(tok, 'POST', '/user/repos', {'name': REPO, 'private': True, 'auto_init': True,
                                                 'description': 'Cloud copy of Scout: full coverage while the home PC is off'})
        print('repo created:', r.get('full_name'))
        time.sleep(3)
    assert r.get('private'), "the repo is not private — stopping"
    put_secret(tok, 'NTFY_TOPIC', cfg['ntfy']['topic'])
    put_secret(tok, 'NTFY_CTL_TOPIC', ctl)
    gh = cfg.get('github', 'token', fallback='').strip()
    if gh:
        put_secret(tok, 'GH_PAT', gh)
    else:                                        # no home token: the workflow uses GitHub's own GITHUB_TOKEN
        st, _ = api(tok, 'DELETE', f'/repos/{OWNER}/{REPO}/actions/secrets/GH_PAT')
        print(f"secret GH_PAT: {'removed' if st == 204 else 'absent' if st == 404 else st}")
    if with_ai_key:
        key_file = os.path.join(ROOT, 'data', 'anthropic_cloud_key')      # a separate, spend-capped key for the cloud
        key = open(key_file).read().strip() if os.path.exists(key_file) else cfg.get('anthropic', 'api_key', fallback='').strip()
        if key:
            put_secret(tok, 'ANTHROPIC_API_KEY', key)
            print(f"ANTHROPIC_API_KEY: from {'data/anthropic_cloud_key (separate cloud key)' if os.path.exists(key_file) else 'the home scout.conf (same key as home)'}")
    for repo_path, local in FILES.items():
        content = open(local, 'rb').read()
        st, cur = api(tok, 'GET', f'/repos/{OWNER}/{REPO}/contents/{repo_path}')
        if st == 200 and base64.b64decode(cur.get('content', '').encode()) == content:
            print(f"{repo_path}: unchanged")
            continue
        body = {'message': f"Update {repo_path}" if st == 200 else f"Add {repo_path}",
                'content': base64.b64encode(content).decode()}
        if st == 200:
            body['sha'] = cur['sha']
        st, _ = api(tok, 'PUT', f'/repos/{OWNER}/{REPO}/contents/{repo_path}', body)
        print(f"{repo_path}: {'ok' if st in (200, 201) else st}")
    for old in SUPERSEDED:
        st, cur = api(tok, 'GET', f'/repos/{OWNER}/{REPO}/contents/{old}')
        if st == 200:
            st, _ = api(tok, 'DELETE', f'/repos/{OWNER}/{REPO}/contents/{old}',
                        {'message': f"Remove {old} (superseded by scout.py --cloud)", 'sha': cur['sha']})
            print(f"{old}: removed ({st})")
    if run:
        time.sleep(5)                                   # GitHub re-parses the workflow file after an upload
        st, d = api(tok, 'POST', f'/repos/{OWNER}/{REPO}/actions/workflows/scout-cloud.yml/dispatches', {'ref': 'main'})
        if st != 204:
            sys.exit(f"run not started (HTTP {st}): {d.get('message', d) if isinstance(d, dict) else d}")
        print('run started')
        run_ = None
        for _ in range(60):
            time.sleep(10)
            st, runs = api(tok, 'GET', f'/repos/{OWNER}/{REPO}/actions/runs?per_page=1&event=workflow_dispatch')
            cand = (runs.get('workflow_runs') or [None])[0]
            if cand and cand['status'] == 'completed' and cand['created_at'] > time.strftime('%Y-%m-%dT%H:%M', time.gmtime(time.time() - 900)):
                run_ = cand
                break
        if not run_:
            sys.exit("the run did not finish within 10 min — see the Actions tab")
        print('run:', run_['conclusion'], run_['html_url'])
        st, z = api(tok, 'GET', f"/repos/{OWNER}/{REPO}/actions/runs/{run_['id']}/logs", raw=True)
        if not (isinstance(z, bytes) and z[:2] == b'PK'):
            sys.exit(f"logs not available (HTTP {st}): {z[:200]!r}")
        zf = zipfile.ZipFile(io.BytesIO(z))
        for name in sorted(zf.namelist()):
            if '/' in name:                             # the job-level files hold the whole log
                continue
            for line in zf.read(name).decode('utf-8', 'replace').splitlines():
                if any(w in line for w in ('[cloud]', '[sync]', '[ALERT]', '[QUIET]', 'lane done', 'Traceback',
                                           'Error', 'error:', 'make_conf', 'Process completed')):
                    print('  ', line.split('Z ', 1)[-1][:160])


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'template'
    if cmd == 'template':
        build_template()
    elif cmd == 'push':
        push(with_ai_key='--with-ai-key' in sys.argv, run='--run' in sys.argv)
    else:
        sys.exit(__doc__)
