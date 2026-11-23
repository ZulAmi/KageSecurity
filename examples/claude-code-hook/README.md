# Post-deploy scan hook for Claude Code (opt-in)

This hook watches the Bash commands Claude Code runs. When it sees a deployment
(`vercel deploy`, `fly deploy`, `kubectl apply`, ...) and the command output contains
a URL whose host **you have allow-listed**, it starts a KageSec scan in the background.

It never scans a host that is not in `KAGESEC_HOOK_ALLOWED_HOSTS`, and it runs in
passive mode (no attack payloads) unless you set `KAGESEC_HOOK_ACTIVE=1`.

## Install

```bash
mkdir -p .claude/hooks
cp examples/claude-code-hook/post_deploy_scan.py .claude/hooks/
# merge examples/claude-code-hook/settings.example.json into .claude/settings.json
export KAGESEC_HOOK_ALLOWED_HOSTS="staging.example.com"
```

Only allow-list hosts you own or are authorised to test.
