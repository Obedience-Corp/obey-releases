# Obedience binary releases

Public release archives and checksums for Obey, the Festival App and required
companions. Obey implementation and private test source stay in the private
producer repository. This repository contains only binary distribution metadata
and generic candidate-verification automation; it never checks out private source.

Obey archives use `obey-<version>-<macOS|linux|windows>-<x86_64|arm64>.tar.gz` and
contain `obey`, `ob` and the existing LICENSE (Windows commands have `.exe`).
Production tags, companion tags and the App updater channel are separate.

## Unpublished native candidates

Private builds must retain CGO for Obey's SQLite driver. Prepare all six target
archives, `checksums.txt` and `candidate.json` as an **unpublished draft** named
`candidate-obey-v<version>-<first-eight-source-characters>`. Never use a production
`v*` tag or publish a candidate as a workaround for missing proof.

The candidate manifest has schema `obey-candidate/v1`, `version`, full
`source_revision`, and exactly six `artifacts` objects, each with the exact
`filename` and lowercase `sha256`. Checksums must describe exactly the same set.
No credentials belong in this manifest or workflow inputs.

After the verifier workflow is on the default branch, dispatch it with:

```sh
gh workflow run verify-candidates.yml --repo Obedience-Corp/obey-releases \
  -f candidate_tag=candidate-obey-vVERSION-SOURCE8 \
  -f version=VERSION -f source_revision=FULL_REVIEWED_SOURCE_SHA
```

Every leg uses a disposable GitHub-hosted machine matching the actual target.
GitHub hides drafts from read-only tokens. A separate data-only fetch job therefore
has contents:write solely to authenticate draft reads. It validates all eight files
without executing candidates, then uploads a same-run artifact. There is no
publication call. Native jobs explicitly retain contents:read, have no draft
download credential, and revalidate artifact hashes/identity before execution. A published tag, partial inventory, bad digest, unsafe archive, wrong binary
identity or wrong runner fails closed.

Before executing either binary, each native job uses Go's build-info reader to
verify both files embed the exact reviewed Git revision, a clean source state,
CGO enabled, and the expected OS/architecture. A matching CLI version stamp alone
does not establish source provenance. The job then checks version/source/platform, starts its own isolated daemon,
verifies real initialized SQLite state and exercises sibling CLI autostart. Mac
binaries retain the macOS12 floor. Windows additionally checks service install,
owned-process crash recovery, restart, sibling wake and uninstall, refusing any
preexisting service. Only fixture PIDs are signaled. These checks do not claim
Apple notarization, Windows trusted signatures, a user's installed App journey or
an updater signature. Those remain separate release acceptance.

All six native proof artifacts must pass before production publication. Publishing
still requires producer approval, immutable final bytes/checksums, anonymous
post-publication verification and authenticated Installer acceptance. Draft
verification does not grant publication authority or waive any failed festival gate.

## Automation checks

Filesystem mutation tests run only in Docker:

```sh
docker run --rm --user 10001:10001 \
  --tmpfs /tmp:rw,exec,size=128m,mode=1777 \
  -e CANDIDATE_TEST_CONTAINER=1 -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$PWD:/src:ro" -w /src python:3.13-slim \
  python -m unittest discover -s tests -v
```

The tests cover identity/inventory/hash/path/link/mode failures, refusal to run
native mutation proofs on an unproven machine, and the privileged-fetch/read-only
execution boundary. Native mode rejects download credentials and never fetches drafts. They do not substitute for the six
real native candidate jobs.
