# aif-insights

Collects AI coding-agent transcripts from a machine, redacts them before they
leave it, and archives them with a per-session summary in Cloudflare R2. This
is phase A1 of the [roadmap](../docs/ROADMAP.md): the data that later phases use
to find where agents struggle and to measure the factory.

It does not import `software_factory` and can be installed on its own.

## What it collects

| Agent | Location | Status |
|---|---|---|
| Claude Code | `~/.claude/projects/<project>/<session>.jsonl`, plus subagents in `<session>/subagents/agent-<id>.jsonl` | Parser tested on real transcripts |
| Codex | `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl` | Summary marked `unverified` until checked against a real file |

Files still being written are skipped until they have been quiet for
`quiet_minutes`. A session that grows later is uploaded again as a new object:
the archive only ever adds objects, so an R2 bucket lock on `raw/` works.

## What leaves the machine

Every JSONL line is parsed and every string is redacted before upload:

- named credential formats: GitHub, Anthropic/OpenAI/Groq, AWS, Slack, Stripe,
  Google, npm, SendGrid, Cloudflare, JWTs, private keys, passwords in DSNs,
  bearer tokens;
- `KEY=value` and `"key": "value"` assignments whose name looks secret
  (`password`, `secret`, `api_key`, `access_token`, …), quoted or not;
- long random-looking tokens (mixed case and digits, high entropy). Git SHAs,
  digests and UUIDs are kept;
- embedded base64 images and documents, and opaque thinking signatures, are
  dropped.

Sessions whose working directory matches `exclude_cwd` are never uploaded. The
per-session index is built from the redacted text, so it can't carry a secret
either. Redaction is broad but pattern-based, so treat the bucket as sensitive
anyway: private, and readable only by the worker and the two of you.

## Archive layout

```
raw/{agent}/{user}/{yyyy}/{mm}/{dd}/{session}/{part}.{digest}.jsonl.gz
index/{agent}/{user}/{yyyy}/{mm}/{dd}/{session}/{part}.{digest}.json
```

`part` is `session` or `agent-<id>` for a subagent. The index object holds the
summary (title, working directory, branches, models, prompts, tool calls and
errors, interrupts, tokens, cost, lines changed), the redaction counts, and the
machine and user it came from.

## Set up a laptop

1. Install it (Python 3.11 or later):

   ```bash
   pipx install "aif-insights[r2] @ git+https://github.com/BrainMatterStudios/AIFactory@main#subdirectory=insights"
   ```

2. Keep local transcripts longer than the 30-day default, so nothing is deleted
   before it is collected. In `~/.claude/settings.json`:

   ```json
   { "cleanupPeriodDays": 3650 }
   ```

3. Write `~/.config/aif-insights/config.toml`:

   ```toml
   user = "ahmed"
   store = "r2"
   quiet_minutes = 30
   exclude_cwd = []            # e.g. ["*/clients/confidential-*/*"]

   [r2]
   account_id = "<cloudflare account id>"
   bucket = "agent-transcripts"
   ```

4. Try it against a local folder first, and look at what would be uploaded:

   ```bash
   aif-insights collect --local ~/aif-insights-preview
   ```

5. Run it hourly. The R2 credentials go in the scheduler's environment, never
   in the config file:

   ```bash
   aif-insights schedule launchd > ~/Library/LaunchAgents/com.brainmatter.aif-insights.plist
   # edit the two REPLACE_ME values, then:
   launchctl load ~/Library/LaunchAgents/com.brainmatter.aif-insights.plist
   ```

   On Linux, or on the VPS for dispatch sessions: `aif-insights schedule cron`.

`aif-insights status` shows how many files this machine has uploaded.

## Development

```bash
cd insights
pip install -e ".[dev]"
python -m pytest -q
```
