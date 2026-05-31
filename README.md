# FSSA Anonymous Report Public Mirror

This repository is an external public mirror of the FSSH/FSSA anonymous report transparency log.

Source API:

```text
https://fssh-anonymous-report.vic0407lu.workers.dev
```

The mirror is produced only from public, redacted API responses. It is intended to make the public transparency log easier to audit outside Cloudflare by preserving snapshots in Git commit history.

## Contents

```text
manifest.json
entries/
  000000001.json
roots/
  latest.json
  YYYY-MM-DD.json
proofs/
  consistency/
    000000001-to-000000001.json
snapshots/
  latest.json
```

## Privacy Rules

This mirror must never contain:

- full `commit`
- full `commit_ref`
- report plaintext
- email addresses
- internal admin account identifiers such as `created_by`
- private keys, tokens, or Worker secrets

Allowed public data includes:

- `commit_digest`
- `commit_redacted: true`
- `commit_ref_redacted: true`
- `leaf_hash`
- `entry_type`
- `timestamp`
- public redacted leaf data
- `root_hash`
- `tree_size`
- public proof objects

## Sync

The GitHub Actions workflow runs hourly and can also be started manually from the Actions tab.

Local run:

```bash
node scripts/sync.mjs
```

The script fails if a public response contains fields that should not be mirrored.

