# FSSA Anonymous Report Public Mirror

This repository is an external public mirror of the FSSH/FSSA anonymous report transparency log.

Source API:

```text
https://report.fssakh.org
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

## How it is updated

Every hour the `fssh-mirror-push` Cloudflare Worker reads the public `/log/*` endpoints (the same redacted
responses anyone can fetch) and adds one commit to `main`. Before committing it checks that the log only grew:
the root recorded here must equal the root of the same prefix of the current log, the consistency proof must
verify (RFC 9162), and files already in this repository must not change. It only fast-forwards `main`; it never
rewrites history. Its GitHub token can write repository contents only, not workflows.

## Verifying

`.github/workflows/verify.yml` runs on every push without secrets or network access. To check a clone yourself:

```sh
node scripts/verify.mjs            # current state, and append-only since the previous commit
node scripts/verify.mjs <commit>   # append-only since an older commit
```

It recomputes the RFC 6962 Merkle root from `entries/`, compares it with `manifest.json`, `roots/latest.json`
and `snapshots/latest.json`, verifies every proof in `proofs/consistency/`, and fails if any entry, proof or past
root file was modified or deleted.
