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
