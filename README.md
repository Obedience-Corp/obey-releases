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

## Published selected-component native proof

`verify-selected-components.yml` uses the actual public Installer0.3.7 and its
official signed marketplace source to install only the App's selected suite,
Camp App companion and Obey packages. The expected receipts are suite0.3.24,
CampApp0.1.0 and Obey0.2.2. Producer URLs/checksums remain in the existing release
and marketplace machinery, rather than a second install catalog.

```sh
gh workflow run verify-selected-components.yml --repo Obedience-Corp/obey-releases
```

The four jobs run on fresh hosted macOS ARM/Intel, Linux x64 and Windows x64
machines with read-only repository permissions and no download credentials. No
private source is checked out. The verifier refuses preexisting ecosystem tools
or Obey supervisor entries, uses an owned temporary managed bin/config/data/socket,
and uninstalls only the service it attempted to register. The fresh disposable
account's real home is retained for native supervisor lookup; this must never run
on an operator account. Receipt/file hashes and exact live versions are checked.

Reports record actual codesign/spctl or Authenticode results without changing
security settings. Windows reports include the read-only raw Smart App Control
policy value, OS version and any query error. Microsoft documents the raw values
and current-policy inspection in its [Smart App Control testing guide](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control).
An absent/inaccessible value remains unknown. Successful native execution under
that runner's policy does not prove consumer SmartScreen UI, reboot, a published
App journey or a signature trust claim. Supervisor warnings and cleanup state
remain explicit in the report.
Read-only Windows queries use the runner's PowerShell7, avoiding cross-edition
module loading from nested Windows PowerShell5.1. A failed query still fails the
job and retains a partial report showing which installation/execution checks
actually completed; partial reports are not successful native acceptance.

## Unpublished App packaging and launch proof

`verify-app-candidates.yml` verifies the actual packaged App on four fresh hosted
native machines (Mac ARM/Intel, Linux x64, Windows x64). It reuses the separate
privileged data-only draft fetch and read-only, credential-free native execution
boundary. No private implementation or private test source is checked out.

Collect four **same-source, same-version** original builder directories, each
containing its `candidate-<target>.json` and declared artifacts. Preserve those
inventories. Use a fresh destination with the data-only collector:

```sh
python scripts/assemble_app_candidate.py --destination app-draft \
  MAC_ARM_DIR MAC_INTEL_DIR LINUX_X64_DIR WINDOWS_X64_DIR
```

It retains the exact bytes/hashes, normalizes asset spaces to dots for GitHub,
and records `original_name`. The resulting `app-candidate.json` uses schema
`festival-app-candidate/v1`, exact `source_revision`, `version`, and a `targets`
map containing the original file records. App binaries do not embed a Git
revision: source identity is validated builder provenance, not an embedded-binary
claim. Never combine different source revisions. Upload only the collected files
to an **unpublished draft** `candidate-app-vVERSION-SOURCE8` under existing release
authority. Verify actual returned asset names/digests against this manifest;
never infer stored names or download URLs from guessed GitHub normalization.

```sh
gh workflow run verify-app-candidates.yml --repo Obedience-Corp/obey-releases \
  -f candidate_tag=candidate-app-vVERSION-SOURCE8 \
  -f version=VERSION -f source_revision=FULL_REVIEWED_APP_SOURCE_SHA
```

Every native leg revalidates the entire inventory and checks its updater payload
with the **pinned production** public key A0880EE086F129E5. A draft or input cannot
replace the trust anchor. Mac proof compares the read-only DMG's copied App to the
authenticated updater archive, verifies macOS12 metadata and structural codesign,
and launches only the owned copy. Windows follows the per-user NSIS `/S` layout
contract, checks live bundled sidecars, launches the installed App and uninstalls
only its own installation. Linux installs the owned deb through apt with dependency resolution, checks the
installed version/layout, and launches it on its own Xvfb. It separately records
the authenticated downloaded AppImage's default launch. If that fails (including
unavailable FUSE), extracted startup is diagnostic only and the proof fails; it
never substitutes extracted success for normal AppImage launch.
The proof requires a live owned window and retains initial,5second and15second
startup captures with alive checks, logs and partial JSON on failures. The primary
PNG points at the late frame. Inspect the images: a blank/error window does not
establish rendered App readiness. It changes no global security settings or existing installation.

This is packaging/launch acceptance only. A license screen/window is not license
access, useful first use, a configured provider, a reboot, consumer SmartScreen/
SAC trust, or an A-to-B update. Reports keep those claims false. Apple Developer ID
and notarization are optional; per-app Open Anyway remains the supported unsigned
macOS path. An unavailable GUI or failed launch remains an explicit failed proof,
not an inferred success from signatures/builds. Never run native mode on an operator
account. Unit/negative filesystem tests run only in the Docker harness below.

Mac failures retain original entitlements, xattr names/hashes/quarantine, execution
policy assessment/logs and matching crash reports. Optional workflow input
`mac_entitlement_diagnostic=true` additionally copies only the owned bundled CLI
into a separately labeled temporary diagnostic directory. It preserves a same-byte
copy control, and ad-hoc signs another copy after removing only
`com.apple.developer.web-browser` and
`com.apple.developer.web-browser.public-key-credential`, preserving every other
entitlement. It never changes original bundle/archive bytes, removes quarantine,
or changes global security policy. A successful modified-copy version probe is
**diagnostic only**; the original candidate remains failed. This option is off by
default and never supplies a release trust root or publication authority.

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

### Published App A-to-B upgrade proof

`verify-app-upgrade.yml` accepts two full reviewed sources whose immutable public
releases are `app-test-SOURCE`. A must already be compiled with B's immutable
`latest.json` endpoint; this harness never replaces an endpoint or trust root.
Both releases retain `app-candidate.json`, `checksums.txt`, production
`SHA256SUMS`, `latest.json` and every declared original artifact/signature.
Anonymous download checks source/version, server digests, both checksum sets and
all five updater keys, including distinct Debian and AppImage payloads.

Five fresh hosted native legs exercise both Macs, Debian, default AppImage and
Windows NSIS. They verify the pinned production updater signatures before install.
A uses its actual automatic updater. Windows invokes the real owned-window
**Update ready → Restart now** button through UIAutomation and requires a new B
process after NSIS installation. Mac/Linux require the installed B payload, a
normal OS quit request and reopening B; extracted AppImage startup cannot qualify.
Signed NSIS reference extraction is compared with installed App/Installer/Activity
files; Mac compares the entire authenticated bundle, Debian its package files and
AppImage the entire authenticated image. B payload checks repeat after reopening.

The fixture provisions the existing three selected public packages, initializes
and registers a real owned Camp with its released CLI, and seeds valid settings
at `~/.obey/festival-app/settings.json`. Readback after install and reopen checks
settings, Camp registration, selected package receipts/file hashes and foreign-file
sentinels. Normal quit and owned cleanup remain distinct; forced cleanup cannot
prove the normal quit step. Always-retained reports/screenshots/logs preserve
failures. No credentials, private checkout, global security changes, stable-feed
mutation or provider/test backdoor is involved. Licensing, useful first use,
reboot, consumer trust and native failure-recovery journeys remain unverified by
this mechanism check. No native upgrade result is claimed until actual published
A/B inputs have run successfully and the artifacts have been inspected.

`verify-appimage-candidate.yml` isolates default AppImage startup on a fresh
Ubuntu runner without first installing Debian or carrying prior App state. It
uses the original draft inventory and production signature, and installs only
verification/display tools. Extraction probes the authenticated bundled CLI and
resource paths; the App launches the original image, never extracted AppRun.
Real delayed frames and logs require inspection: a live captured window alone
cannot establish healthy rendering. No rendering/security override or extracted
fallback qualifies this lane. The previous combined Debian/AppImage white frames
remain separate evidence.
