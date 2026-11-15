# scout-cloud

The cloud copy of Scout, the threat-intelligence watcher that normally runs on the home PC. GitHub Actions runs
`scout.py --cloud` every 30 minutes:

- **Home alive** (it posted "alive" to its heartbeat topic in the last 45 min) → a *quiet* run: every source is read
  and remembered, the journal is kept, nothing is pushed. The cloud's memory stays in step with home.
- **Home silent** → the full Scout runs here, with ☁ in every title, until home reports alive again.

State (seen.json, journal, outbox, the Confirmed window) lives in the Actions cache between runs. Secrets
(`NTFY_TOPIC`, `NTFY_CTL_TOPIC`, optional `ANTHROPIC_API_KEY` and `GH_PAT`) are Actions secrets; the config is built
from `cloud/scout.cloud.conf` at run time and written outside the cached folder.

Update from the home PC: `python3 cloud/deploy.py push` (needs a GitHub token with `repo` + `workflow`).
