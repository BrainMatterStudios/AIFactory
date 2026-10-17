// AIFactory Leash 1.1.7 base policy.
//
// Cedar is default-deny. The request workspace token below is deliberately
// non-matching in the installed base file; the root-owned bridge appends one
// exact request overlay in guest state for each scoped turn. It grants reads to
// that request workspace and writes only to the lifecycle-authorized paths.

// Keep explicit denials ahead of broader directory permits so the policy stays
// fail-closed under both direct Cedar evaluation and Leash's translated rule
// evaluation. Default-deny also covers all other paths outside the request
// authority, including /Users/ host paths which are never mounted.
forbid (
  principal,
  action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"],
  resource
) when {
  resource in [
    File::"/var/run/docker.sock", File::"/run/docker.sock",
    Dir::"/var/lib/aifactory/", Dir::"/etc/aifactory/"
  ]
};

forbid (
  principal,
  action == Action::"ProcessExec",
  resource
) when {
  resource in [
    File::"/usr/bin/docker", File::"/usr/local/bin/docker",
    File::"/usr/bin/sudo", File::"/bin/sudo", File::"/usr/bin/su", File::"/bin/su",
    File::"/usr/bin/ssh", File::"/usr/bin/gh"
  ]
};

forbid (
  principal,
  action == Action::"NetworkConnect",
  resource
) when {
  resource in [
    Host::"169.254.169.254", Host::"169.254.169.254:80", Host::"169.254.169.254:443",
    Host::"metadata.google.internal:443", Host::"github.com:443", Host::"api.github.com:443",
    Host::"registry.npmjs.org:443", Host::"pypi.org:443", Host::"files.pythonhosted.org:443",
    Host::"10.0.0.0", Host::"172.16.0.0", Host::"192.168.0.0",
    Host::"localhost:22", Host::"localhost:1433", Host::"localhost:5432"
  ]
};

// Container operating-system reads required for dynamic linking and tools.
permit (
  principal,
  action in [Action::"FileOpen", Action::"FileOpenReadOnly"],
  resource
) when {
  resource in [
    Dir::"/bin/", Dir::"/sbin/", Dir::"/usr/", Dir::"/lib/",
    Dir::"/lib64/", Dir::"/etc/", Dir::"/proc/", Dir::"/sys/", Dir::"/dev/"
  ]
};

// Container-only scratch and Leash runtime state. Controller authority under
// /var/lib/aifactory and /etc/aifactory is not included.
permit (
  principal,
  action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"],
  resource
) when {
  resource in [
    File::"/root/.claude.json",
    Dir::"/tmp/", Dir::"/leash/", Dir::"/root/.cache/", Dir::"/root/.claude/"
  ]
};

// Exact request root marker. The effective policy generator replaces this
// authority with Dir::"/srv/aifactory/workspaces/<context>/" and narrower File
// or Dir write permits; no static workspace-wide write permit exists here.
permit (
  principal,
  action in [Action::"FileOpen", Action::"FileOpenReadOnly"],
  resource
) when {
  resource in [Dir::"/srv/aifactory/workspaces/__CONTEXT_DIGEST__/"]
};

// Anthropic model and first-party authentication only. GitHub, package
// registries, metadata, RFC1918, SSH, SQL Server and Postgres have no permit
// and therefore remain denied.
permit (
  principal,
  action == Action::"NetworkConnect",
  resource
) when {
  resource in [
    Host::"api.anthropic.com:443",
    Host::"claude.ai:443",
    Host::"mcp-proxy.anthropic.com:443",
    Host::"platform.claude.com:443"
  ]
};

// Required container commands. Executable files remain constrained by the
// filesystem policy and the bridge supplies a bounded environment/argv.
permit (
  principal,
  action == Action::"ProcessExec",
  resource
) when {
  resource in [
    Dir::"/bin/", Dir::"/usr/bin/", Dir::"/usr/local/bin/", Dir::"/opt/",
    File::"/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe",
    Dir::"/srv/aifactory/workspaces/__CONTEXT_DIGEST__/"
  ]
};
