# Repository scope

This repository distributes Obedience binaries and verifies the artifacts it
hosts. It does not own application builds or general product acceptance.

- Keep README.md focused on products, downloads and current release status.
  Maintainer procedures belong in docs/. Investigation history belongs in the
  existing work records, with stable links to original evidence.
- Producers own source, builds, versioning, signing and publication. Never copy
  private implementation or private test source into this public repository.
- Public verification covers artifact identity, archive/checksum/signature
  integrity, native package launch, basic service health and update mechanics.
  Complete setup, shell, provider, preservation and recovery journeys belong to
  the existing private integration lab. Product unit tests belong to producers.
- Existing broader workflows remain transitional until their replacements are
  proved. Read docs/verification.md before changing or retiring them.
- Preserve published tags, asset names, hashes, updater feeds and marketplace
  references. Repository cleanup is not permission to delete or republish releases.
- Keep draft download credentials separate from native execution. Use disposable
  machines and the existing ownership/cleanup checks; never run service or
  filesystem mutation fixtures against an operator's live installation.
- Use the existing CI commands and isolation requirements. Prove changed native
  behavior on the affected platform. Documentation-only edits need link and
  readability checks, plus any branch-required checks still in effect.
- Add a verification responsibility only when a named release requirement and
  owning workitem justify it. Do not turn a failed scenario into an open-ended
  repository-wide testing project or add historical run narratives to the README.
- Report exactly what passed, failed or remains unrun. A successful package check
  does not establish full product readiness or approval to publish.
