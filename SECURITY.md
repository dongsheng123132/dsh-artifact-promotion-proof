# Security

Report vulnerabilities privately through GitHub Security Advisories. Never attach credentials, raw deployment logs, authorization headers, cookies, private keys, source archives or artifact bodies.

The verifier is offline and non-executing. It rejects traversal, symlink inputs, oversized manifests, malformed hashes, duplicate receipt identifiers, secret-shaped material and raw/log/body/content fields. Artifact writes stay inside an explicit workspace-relative directory and are verified by read-back.

A conforming receipt chain is not cryptographic authentication and is not proof that a deployment occurred or is healthy. Pair this verifier with trusted deployment recorders, signed provenance and runtime observation where those properties matter.
