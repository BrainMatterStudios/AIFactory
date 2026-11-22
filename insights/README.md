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

Sessions that touch a folder matching `exclude_cwd` are never uploaded, and
neither are their subagents. While an exclusion list is set, a file with no
known working directory is held back too. The per-session index is built from the redacted text, so it can't carry a secret
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

## Set up a Mac (one step)

Have ready: your R2 account ID, the bucket name, and the Access Key ID and
Secret Access Key of an R2 API token scoped to that bucket with "Object Read &
Write". Then paste:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/BrainMatterStudios/AIFactory/main/insights/install.sh)"
```

The script installs pipx (via Homebrew) if needed, installs `aif-insights`, and
runs `aif-insights setup`. Setup asks for your name, account ID, bucket, the two
keys (typed hidden), and the folders that must never be uploaded. Have that list
ready, because the first upload starts as soon as setup finishes. It then:

- stores the keys in your login Keychain. They never go in a file;
- writes `~/.config/aif-insights/config.toml` (no secrets);
- sets `cleanupPeriodDays` in `~/.claude/settings.json`, so Claude Code stops
  deleting transcripts after 30 days;
- checks the R2 connection with a small test upload under `health/`;
- installs an hourly launchd job and starts it. The first run uploads your
  existing history in the background, which can take a while.

Progress is in `~/Library/Logs/aif-insights.log`; `aif-insights status` shows
the totals. Re-running setup is safe, and keys already in the Keychain are
reused.

If you already have `aif-insights` installed, `aif-insights setup` alone does
the same. To preview what would be uploaded without touching R2:
`aif-insights collect --local ~/aif-insights-preview`.

To change the exclusions later, re-run setup or edit `exclude_cwd` in the config,
for example `exclude_cwd = ["*/clients/acme/*"]`. That pattern covers the folder
itself and everything below it. Adding a pattern does not delete what was already
uploaded.

On Linux or the VPS, put the keys in `AIF_R2_ACCESS_KEY_ID` and
`AIF_R2_SECRET_ACCESS_KEY` and use `aif-insights schedule cron`.

## Development

```bash
cd insights
pip install -e ".[dev]"
python -m pytest -q
```
