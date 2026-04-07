# Spec Pin

Leaf Eater targets a specific revision of the IETF PLANTS MTC draft. This file
records which revision, a SHA-256 of the local copy, and the procedure for
bumping to a newer revision.

## Current Pin

| Field | Value |
|---|---|
| Draft | `draft-ietf-plants-merkle-tree-certs-02` |
| Published | 2026-03-02 |
| Local copy | `~/work/reference/pki-standards/post-quantum/draft-ietf-plants-merkle-tree-certs-02.txt` |
| SHA-256 | `cb13f017c18fe6361efbc93a1d9a5389741eebfeadd8f0aa4bee5c32bdb69c7e` |
| Rule suffix | `_d02` |

Recompute the SHA-256 with:
```bash
sha256sum ~/work/reference/pki-standards/post-quantum/draft-ietf-plants-merkle-tree-certs-02.txt
```

## Bump Procedure

When a new draft revision is published:

1. Download the new draft text into `~/work/reference/pki-standards/post-quantum/`.
2. Recompute the SHA-256 and record it in this file alongside the new revision.
3. Create a new rule suffix `_d<NN>` for any new or changed rules; keep old `_d02`
   rules in place until all callers are migrated.
4. Run the full test suite and fixture set against both rule sets.
5. Update the "Current Pin" table and the version string in
   `cmd/leafeater/main.go`.
6. Update `NOTICE` if the list of files derived from the draft text changes.
7. Update `README.md` status section.
8. Bump `CHANGELOG.md` with a new Unreleased entry noting the draft bump.
