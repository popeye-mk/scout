#!/usr/bin/env python3
"""Build the cloud copy's scout.conf: cloud/scout.cloud.conf (products, lanes, mutes… no secrets, committed) with the
secrets filled in from the environment (GitHub Actions secrets). Written to $SCOUT_CONF, outside the cached data/."""
import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
template = open(os.path.join(HERE, 'scout.cloud.conf'), encoding='utf-8').read()
values = {
    'NTFY_TOPIC': os.environ.get('NTFY_TOPIC', '').strip(),
    'NTFY_CTL_TOPIC': os.environ.get('NTFY_CTL_TOPIC', '').strip(),
    'ANTHROPIC_API_KEY': os.environ.get('ANTHROPIC_API_KEY', '').strip(),
    'GH_PAT': os.environ.get('GH_PAT', '').strip(),
    'WORKSPACE': os.environ.get('GITHUB_WORKSPACE', os.getcwd()),
}
for required in ('NTFY_TOPIC', 'NTFY_CTL_TOPIC'):
    if not values[required]:
        sys.exit(f"make_conf: the secret {required} is not set")
out = re.sub(r'\$\{(\w+)\}', lambda m: values.get(m.group(1), ''), template)
dest = os.environ.get('SCOUT_CONF') or sys.exit("make_conf: SCOUT_CONF (where to write) is not set")
with open(dest, 'w', encoding='utf-8') as f:
    f.write(out)
os.chmod(dest, 0o600)
print(f"make_conf: {dest} written ({'AI on' if values['ANTHROPIC_API_KEY'] else 'AI off'}, "
      f"{'GitHub token' if values['GH_PAT'] else 'no GitHub token'})")
