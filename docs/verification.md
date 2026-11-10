# Verification workflows

Use a workflow for a specific release question. A successful run proves only its
selected platforms and modes. It does not automatically establish full product
readiness or authorize publication.

| Question | Current workflow | Required input |
| --- | --- | --- |
| Do the six Obey archives have the correct identity and run natively? | `verify-candidates.yml` | Draft tag, version, full source revision |
| Can the official installer install the declared selected components? | `verify-selected-components.yml` | Currently pinned component set in the script; review it first |
| Does the App package validate and launch? | `verify-app-candidates.yml` | App draft tag, version, full source revision, platform scope |
| Does the original AppImage launch on a separate fresh host? | `verify-appimage-candidate.yml` | App draft tag, version, full source revision |
| Does the actual signed App update mechanism work from A to B? | `verify-app-upgrade.yml` | Immutable A/B sources and versions, package format and mode |

For an invited beta with no automatic feed, select `mechanism=manual` in the
existing upgrade workflow. It quits the owned A normally, installs B from the
published DMG/NSIS/Deb or replaces the AppImage, verifies B's exact authenticated
payload, then quits and reopens B. Existing fixture settings, camp registration,
selected component identities and foreign-file checks still apply. FA0027's
manual beta handoff is the release requirement for this mode.

Reports name the mechanism and separate `manual_update_verified` from
`automatic_update_verified`; `two_version_update_verified` alone is insufficient
to claim an automatic update. Manual mode rejects updater failure/retry options
and never changes a feed, signature trust root or app endpoint. It does not prove
production license access, browser trust, reboot or a user's complete first-use
journey. Those remain separate acceptance work in the private integration lab.

For example, after the producer has prepared the candidate draft:

```sh
gh workflow run verify-candidates.yml --repo Obedience-Corp/obey-releases \
  -f candidate_tag=candidate-obey-vVERSION-SOURCE8 \
  -f version=VERSION -f source_revision=FULL_SOURCE_SHA
```

Replace all three placeholders with matching reviewed values. Check existing
runs before dispatching. Draft-download jobs validate data with their repository
token; native jobs receive validated artifacts and must not receive that token.

Obey 0.6.0 and later Linux candidates must include exactly `obey`, `ob`, `LICENSE`,
`obey-pty-acquire` and `install-terminal-input.sh`. Both helper files are required
and executable; links, duplicates, additional paths and missing payloads fail
verification. Earlier Linux candidates and all macOS/Windows candidates retain
their three-file contract. This archive check supports the Linux terminal-input
distribution requirement tracked by WI-1634f0; administrator authorization and
provider input acceptance remain producer/private-lab responsibilities.

Anonymous selected-component downloads retry transient gateway/transport failures
up to four attempts with bounded backoff. Each attempt downloads the complete
artifact; byte limits and checksum verification remain required. Permanent HTTP
errors, invalid TLS, oversized payloads and checksum failures are not retried.

The released-Installer transport control uses the live signed catalog. It records
successful package versions, executable versions, receipts and physical files
before blocking the companion download, then verifies those exact earlier files
and receipts through failure and retry. Historical beta version constants remain
specific to their original App acceptance fixtures.

## Manual replacement before B is published

FA0034 requires a licensed 0.1.5 A to be replaced by the original free B before
public delivery. The existing upgrade workflow accepts optional
`b_candidate_tag=candidate-app-vVERSION-SOURCE8` with `mechanism=manual`.
A remains the exact published immutable release. The input job downloads B with
its read-only repository token using the existing qualification-draft validator.
Native jobs receive the checked inventory/payloads without that credential,
recheck source/version/hashes and production signatures, and exercise the same
manual DMG/NSIS/Deb/AppImage replacement path. Draft input is refused in updater
mode. Reports identify B as `qualification-draft` and explicitly leave
`b_anonymous_download_verified=false`. Public discovery still requires the later
anonymous published-byte check; no manifest or publication record is fabricated.

For Windows default-home proof, `b_readiness=free-workspace` explicitly requires
Projects and Activity after B installation and reopen, rejecting the old license
screen. Manual A is checked for the licensed surface first. The default remains
`licensed`, preserving historical verification. Surface visibility establishes
shell readiness only; useful work, legacy vault variants and complete preservation
remain private-lab acceptance and cannot be inferred from these flags.

The free-workspace fixture uses the released Installer 0.3.12 and records each
successful official stable selection, its catalog commit and exact manifest/signature
bytes, suite executable versions, and receipt file hashes before launching A.
All later comparisons use that frozen baseline rather than querying newer expected
versions. Historical licensed fixtures retain their original beta pins. No signing
policy, provider requirement, updater feed or App source tag changes in this mode.

```sh
gh workflow run verify-app-upgrade.yml --repo Obedience-Corp/obey-releases \
  --ref REVIEWED_VERIFIER_REF \
  -f mechanism=manual -f failure_mode=none \
  -f a_source=FULL_PUBLISHED_A_SHA -f a_version=A_VERSION \
  -f b_source=FULL_CANDIDATE_B_SHA -f b_version=B_VERSION \
  -f b_candidate_tag=candidate-app-vB_VERSION-B_SOURCE8 \
  -f b_readiness=free-workspace \
  -f package_format=all -f installation_context=redirected
```

Check for existing runs before dispatching. For the separate Windows default-home
surface and relaunch check, use the same reviewed inputs with `package_format=nsis`
and `installation_context=default-home`. Retain the verifier commit and reports
as supplemental proof; this does not modify the producer's pinned packaging verifier.

## Transitional product tests

`verify-app-fresh-setup.yml` and `verify-linux-clean-vm.yml` currently run broader
setup, preservation, recovery and reboot scenarios. Upgrade verification also
contains broader user-state/recovery modes. Their future owner is the existing
private integration lab; retain current paths until destination execution passes.

`verify-discovery-proof.yml` runs an internal Obey test executable. The cleanup
plan consolidates this with Obey's existing private native test job after matching
case coverage is demonstrated. Do not delete its historical drafts as part of
that code change.

`verify-automation.yml` tests these harnesses. At the audit it runs native checks
on every PR. Keep existing required gates until path-scoped replacements are
validated. Use its Docker commands for filesystem mutation tests, and disposable
native runners for platform-specific helper behavior.

Native reports, UI captures and persisted-state readbacks are the evidence for
the behavior selected. Keep original failures as failures; later reruns have
their own identities. The historical README linked from the maintainer index
contains the old detailed modes and investigations while this split is underway.
