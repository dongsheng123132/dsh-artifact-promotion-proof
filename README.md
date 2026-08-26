# DSH Artifact Promotion Proof

An offline, deterministic evidence layer for DeepSeek Harness supply chains. It checks whether one explicit artifact digest followed a declared build → staging → production chain with the exact environment bindings, predecessor receipts and gate evidence required at every stage.

It **does not deploy** anything, call a registry, grant approval, verify runtime health, or mutate an environment. It also **does not authenticate** receipts or verify provenance signatures. A `promoted` verdict means only that the supplied hash-only records are internally complete, ordered and policy-conformant.

## Complementary boundary

- `dsh-release-proof` compares download endpoints for HTTP, length, version and SHA-256 agreement.
- `dsh-attestation-proof` verifies DSSE/in-toto signatures, subjects and signer thresholds.
- `dsh-reproducible-build-proof` compares independent rebuild outputs.
- `dsh-build-hermeticity-proof` checks one recorded build's declared external-influence closure.
- `dsh-output-custody-proof` checks how a DSH tool result is projected, spilled and durably recorded.
- This plugin checks zero-rebuild promotion continuity across declared deployment stages. `dsh-evidence-arena` promotes a selected coding worktree into a repository; this plugin never writes a candidate or repository.

Every stage must appear exactly once and in order. The artifact digest, stage/environment hash and predecessor deployment receipt must remain continuous. Required gate types must appear once, bind the same artifact, precede promotion and meet the stage's distinct-authority threshold. Missing, stale, reordered, cross-artifact or extra gate evidence fails closed.

## Install

```bash
dsh plugin --profile evidence add github:dongsheng123132/dsh-artifact-promotion-proof#COMMIT
```

The bundle exposes `dsh_artifact_promotion_inspect` and `dsh_artifact_promotion_verify` from one headless core. The independent MCP stdio server exposes `artifact_promotion_inspect` and `artifact_promotion_verify`. The CLI accepts `inspect` or `verify` plus an explicit JSON path.

See [`examples/promoted.json`](examples/promoted.json). Reports contain only hashes, counts, booleans, gate classifications and verdicts. Secret-shaped material and raw log/body/content fields are rejected. The DSH verify tool reads a workspace-relative non-symlink manifest, writes only to an explicit workspace-relative `artifactDir`, creates deterministic content-addressed output exclusively, and verifies it by read-back.

```bash
npm test
npm run check
npm run smoke:plugin
npm run smoke:mcp
python C:/Users/YOU/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py .
```

Node.js 22 or newer is required. The verifier has no runtime dependency, spawns no process and makes no network request.
