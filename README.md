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
CampApp0.1.0 and Obey0.2.3. Producer URLs/checksums remain in the existing release
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
on an operator account. Integration/file hashes and exact live versions are checked.

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
inventories.

New App inventories declare `installer_basename: "festival-app-installer"`.
All four targets must agree, and the collector preserves that field in the
aggregate manifest. Historical v1 inventories without the field retain their
original `festival` layout. Unknown names and mixed layouts are rejected.
Native, updater and reboot checks use the declared private executable; they
never select a coexisting system `festival` command as the App's Installer.

Use a fresh destination with the data-only collector:

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

Filesystem mutation tests run only in Docker. The test image includes Zsh so
its real-shell contracts execute rather than skip:

```sh
docker build -t obey-release-shell-contracts:local - < tests/Dockerfile.shells
docker run --rm --user 10001:10001 \
  --tmpfs /tmp:rw,exec,size=128m,mode=1777 \
  -e CANDIDATE_TEST_CONTAINER=1 -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$PWD:/src:ro" -w /src obey-release-shell-contracts:local \
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

The Linux native GUI lanes provision a normal Ubuntu desktop graphics baseline:
`libegl1`, `libegl-mesa0`, `libgles2`, `libgl1` and `libgl1-mesa-dri`, with actual
versions recorded in job logs. The minimal hosted server/Xvfb image can lack EGL;
original fresh run39995756136 failed before a window with missing `libEGL.so.1`.
That failure remains preserved. The normal desktop baseline is justified by
[AppImage's host-resource contract](https://docs.appimage.org/introduction/concepts.html),
its [graphics-driver exclusion policy](https://github.com/AppImageCommunity/pkg2appimage/blob/master/excludelist),
and [Ubuntu24's Mutter desktop dependencies](https://packages.ubuntu.com/noble/libmutter-14-0).
Do not bundle graphics-driver libraries to hide that fixture omission. This lane
still installs no Festival App Debian package and uses no rendering or security
environment override; it does not claim a graphical App works on an unprovisioned
headless server or prove every desktop/GPU combination.

Linux Debian verification logs a checked `--simulate` apt transaction before dependency transfer. Simulation cannot install even if host configuration forces Assume-Yes; the real download logs its exact size.
Network preparation is a separate, bounded 30-minute `--download-only` operation;
the actual `--no-download` install retains its five-minute budget. These are fresh
hosted machines, with GNU `timeout` running under the same sudo scope as apt: TERM
and a 15-second KILL grace apply to the owned process group, rather than killing
only a sudo wrapper and leaving a package lock holder. Cleanup uses the same
bounded group ownership. A timeout remains a failure, with partial stdout/stderr
retained; there is no retry or global process cleanup.

This network allowance follows A run40001857008: the desktop prerequisite step
fetched26.6MB in638seconds, while the later five-minute apt invocation timed out
without retained partial output. The cause of that later delay was not established.
A minimal Ubuntu24 container's dependency plan needs163MB of downloads; the actual
hosted plan is logged because its installed baseline differs. The 30-minute bound
can still fail on a slow mirror; it is not a guarantee or a product startup budget.
Linux packaging/upgrade jobs allow60minutes for prerequisite setup, dependency
transfer, the original installation budget, native proof and owned cleanup. Other
OS budgets are unchanged. No producer artifact bytes or runtime/security settings
change for this harness repair.

Upgrade fixtures initialize the released Camp noninteractively with explicit name,
description and mission, plus `--no-git --no-skills`, then require its real registry
entry and persisted camp metadata. Current `camp init --help` must expose all five
flags. The first five-leg run failed before App installation because description
and mission were omitted; those failures are retained, not treated as updater
failures. The corrected invocation was verified with the public suite's actual
Camp binary in a disposable container and the registry/config read back afterward.

Debian's no-download local archive handling can fail on a renamed downloaded Deb.
After dependency download, the verifier now runs exact-byte `dpkg --unpack` and
checked `apt-get --no-download --no-remove --fix-broken install` in one owned
300-second group. Failed unpack cannot proceed to apt; missing cached dependencies
fail without silently removing the partial App. The isolated root-container
integration installs a real local package/dependency through loopback HTTP (Docker
blocks external network), then proves missing-cache failure, unpacked state and
owned purge. Root privilege is confined to that disposable package database.

The existing upgrade workflow defaults to all five declared formats. Optional
`package_format=deb` verifies only the remaining Debian leg after the four other
formats already qualified; unsupported input fails before native execution. This
does not narrow supported platforms or replace their preserved native evidence.

Windows captures now identify the App by PID, start time, executable path and
window handle, temporarily expose only that window, and save its actual displayed
frame rather than the entire desktop. The prior upgrade proof retained valid
payload/restart/preservation evidence, but terminal windows obscured the reopened
App image. The capture restores the original topmost state in `finally` and
records visible UI Automation names alongside the image. It refuses stale process
identity, hidden/minimized windows and a covering window at the frame's center.
When the owned frame extends beyond the disposable desktop, capture uses normal
window maximization and restores the original placement afterward. Empty frames
or frames still outside the desktop fail with original/current/display bounds.
This uses the documented [SetWindowPos](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowpos)
window-ordering operation; it does not minimize unrelated windows or change
security settings. Native Windows CI puts a blue fixture window above a red target,
rejects a stale process identity, verifies the captured target pixel and checks
topmost-state restoration. An oversized fixture also verifies rendered pixels and
placement/topmost restoration after success and a failed image write. This covers
the real App's larger default window, which the initial small fixture missed.
Fixture proof is separate from actual packaged App proof.
`package_format=nsis` selects the existing Windows upgrade leg for that follow-up;
the default still runs all five formats. A real native rerun and image inspection
are required before claiming the reopened App renders correctly.

`installation_context=default-home` with `package_format=nsis` exercises selected
packages in the fresh hosted account's normal `~/.obey/installer` directory.
It refuses preexisting ecosystem state and tool/config environment overrides;
it does not inject `FESTIVAL_HOME`, `OBEY_CONFIG` or a managed-bin PATH. The original
redirected fixture remains the default for the five-format mechanism matrix.
This additional journey invokes A's actual Update ready / Restart now control,
then checks that NSIS-auto-restarted B and normally reopened B leave setup and
display the enforced licensing screen. A's modal hides the underlying page from
UI Automation, so the verifier does not wait for inaccessible underlay text before
invoking Restart now. B still requires unobscured licensing UI. It records the bundled
installer's default-environment status, requires all selected tool versions/paths,
and rejects rewritten current executable mtimes as well as changed hashes.
The daemon log is retained before owned service cleanup. The hosted account is
discarded; default-home files are not removed recursively by the verifier.

This diagnoses the earlier mismatch between NSIS auto-restart and a direct launch
with process-only overrides. It does not prove that environment inheritance was
the cause, inspect another process's environment, or claim license access, chat,
fresh component setup, reboot or consumer Windows trust. Actual native results
and original screenshots must still be reviewed before accepting the journey.

## Fresh public default-home setup

`verify-app-fresh-setup.yml` exercises the published App on a fresh disposable
native account, using anonymous immutable `app-test-SOURCE` bytes and the pinned
production updater key. It installs no selected component fixture and makes no
installer/config/PATH override: the App must provision its selected three packages.
The proof waits for setup to leave the package screen, validates official receipts,
file hashes, sidecar status paths/capabilities and a loaded responsive default Obey
service, then normally quits and reopens the App and repeats readback. It preserves
the default daemon log before uninstalling only the service/App it created.
The uploaded proof retains original public release metadata, inventory, both
checksum documents and updater manifest, plus the selected payload name/hash.

Mac ARM/Intel, Debian, default AppImage and Windows NSIS each use a separate fresh
machine. Linux runs normal desktop graphics/window-manager dependencies; Deb never
provides dependencies or state to the AppImage leg. Windows requires visible
licensing UI; Mac/Linux retain delayed setup and reopened frames for explicit
image inspection. Integration/service readiness alone does not prove rendered UI.

These lanes do not establish licensing,
useful first work, provider control, reboot, consumer trust or failure recovery.
A Licenses window alone cannot satisfy the setup result.

The fresh verifier accepts explicitly declared XDG paths only when they equal the
account's normal `.config`, `.local/share` or `.local/state` path. It retains those
values unchanged in the report; foreign, relative and symlink redirects fail. The
official Ubuntu24 image explicitly declares its normal XDG config path in
[configure-environment.sh](https://github.com/actions/runner-images/blob/ubuntu24/20261012.334/images/ubuntu/scripts/build/configure-environment.sh).
`platform_scope=linux` targets only the two Linux packages when repairing that
baseline; the default remains all five native legs, and invalid scope fails.

## Native offline update check and same-process retry

The existing upgrade workflow's opt-in `failure_mode=offline-check` requires
`package_format=nsis` and `installation_context=redirected`. Default none/all-five
coverage is unchanged. A must contain the real native **Check for app updates**
menu and already target the immutable B feed. Old A/B artifacts are not modified.

An owned loopback CONNECT proxy blocks the child App's update transport, while
real TLS, feed URLs and pinned production signatures stay intact. Actual UI
Automation invokes the menu; a visible update-check error and a newly observed
blocked request are mandatory. A's installed payload and retained user/component
state must remain unchanged. The same PID then retries through the same menu
after tunnels to the exact public GitHub asset hosts are enabled; existing real
Restart now, B payload/version, normal reopen and preserved-state checks follow.
The proxy changes only the disposable child environment, never system/user proxy
settings, certificate trust or licensing. Unknown destinations are denied; no
headers, credentials or TLS contents are recorded.

Reports distinguish this one transport-failure recovery case from signature/feed
corruption, rollback, other-OS failure cases, reboot or useful licensed work. A
missing/effectless proxy, changed A state, wrong PID, absent real menu, wrong B
payload or incomplete owned cleanup fails the run. The normal hosted WinForms
fixture exercises actual menu invocation and stale-identity refusal before native
candidate evidence may rely on it. No new native run is accepted from unit tests.

### Internal Windows observer proof (not a product release)

`verify-discovery-proof.yml` is manual-only. It accepts an unpublished
`candidate-sessiondiscovery-FULL_SOURCE_SHA` draft containing exactly
`sessiondiscovery.test.exe` and `sessiondiscovery-proof.json`. The v1 manifest
binds the frozen source, SHA256, Go 1.26.0, Windows amd64 and CGO=0 to an
`internal-observer-test-only` purpose. The data-only draft fetch has write
permission solely to read drafts; the disposable Windows execution job receives
no draft credential. Both jobs validate the fixed inventory and digest. Native
execution additionally checks embedded clean Git provenance, package/build tag,
and runs only `^TestWindowsProcessObservationFS_` with the disposable guard.
Logs, build information and a result report survive test failure. Private source
and test source are never checked out here. This internal observer proof does
not establish production daemon, CGO/SQLite, provider chat or release readiness.

Windows capture writes flushed stage diagnostics, saves owned-window pixels and
restores placement/topmost state before querying accessibility. The text query
runs read-only in a separate owned process with a 15-second bound. A failed text
query retains the PNG plus explicit `uia_verified=false`/`uia_failure`; it never
satisfies strict licensing/setup text readiness. The disposable native fixture
includes a real blocked accessibility provider and verifies pixels/restoration
survive while text readiness remains false. The packaging workflow defaults to
all four targets; `platform_scope=windows` rechecks the complete immutable draft
inventory while executing only the outstanding Windows leg. Invalid scopes fail
before download/execution. No candidate bytes, runtime environment, trust root,
security policy or native acceptance are changed by this selection.

Redirected Windows packaging writes a real owned daemon config/data/socket before
App startup. A read-only task/script-AST/process snapshot must establish the
current user's exact task wrapper, literal executable and config ownership before
calling the owning CLI's service uninstall. Preexisting, foreign, partial or
ambiguous supervisor artifacts are refused. Task/files/socket/process readback
must be empty before temporary files are deleted. A detached instance receives
only normal stop through its unique fixture config. No arbitrary PID/name kill
or default-home service acceptance is inferred. The existing fresh-default
service lifecycle checks remain strict and unchanged.


Fresh Windows setup retains the exact checked `windows-discovery-after-reopen.log`
snapshot and its digest separately from the later full default daemon log, requiring
nonempty runtime evidence and absence of the prior Unix-utility/provider
session-discovery failure messages after normal reopen. Exact Obey0.2.3 receipts
and resolved executable versions are required; this does not prove provider chat
or licensed useful work. Historical0.2.2 packets remain unchanged.

An original Linux window timeout now retains the owned root/descendant PID birth,
state and executable paths, isolated X-display window inventory and a separately
labeled diagnostic desktop image. No environment/credential dump, process signal,
security workaround or timeout inflation is used, and diagnostics cannot turn a
failed primary launch into success. `package_format=appimage` selects only the
outstanding AppImage upgrade leg; default all-five and complete A/B input checks
remain unchanged.

### Existing managed Obey users

The public default-home setup workflow accepts `existing_user=older-idle` or
`current`; its default `none` still runs the unchanged fresh-install scenario.
Both explicit existing scenarios seed current official suite/camp-app/Obey,
a registered fixture camp, user preferences and foreign files on a guarded
fresh hosted account. The older scenario then stops the fixture-owned service,
verifies the actual public0.2.2 archive/checksums and replaces exactly the two
owned Obey binary files and their matching receipt version/hashes. This is
explicit fixture preparation, not an Installer historical-version feature.
The initial runtime version, receipt hashes and idle service are read back.

A recent `lastUpdateCheckAt` prevents the ordinary background check from hiding
the minimum-version behavior. Original public App bytes must update0.2.2 to0.2.3,
restart the idle service, preserve other selected packages/settings/foreign files,
and preserve current bytes, mtimes, receipts and daemon PID on normal reopen.
The separate current scenario checks no-op behavior from the first launch,
including the service unit hash and mtime. All underlying fresh/package guards,
original App signature checks and owned service cleanup remain in use. Reports
set `existing_user_reconciliation_verified`, never `fresh_default_setup_verified`,
for seeded scenarios. Actual captured screens still require review.

The seeding helper deliberately preserves an existing user's shell-setup opt-out;
these scenarios do not prove ordinary new-shell integration, active-session
continuity, licensed access or useful first use. The old Windows daemon's retained
log can contain its known Unix-discovery errors, so the older scenario preserves
that full mixed-version log without claiming it is error-free. The separate
fresh0.2.3 scenario retains its strict Windows discovery-log assertion.

The Windows offline retry verifier uses UIAutomation for managed MenuStrip controls and guarded real pointer input for a Win32 native menu. Native interaction requires the exact owned PID/path/start identity, exact enabled App → Check for app updates labels, owned foreground window, valid menu bounds and an unobscured owned point. It sends no command ID or application event; actual request/proxy failure, unchanged A and same-PID recovery remain independently required. Pointer position is restored and native-menu stage metadata is retained. The disposable fixture includes an actual SetMenu/WM_COMMAND receiving window as well as the previous MenuStrip control; stale identities must fail before input.

The native bounds contract follows Microsoft's [GetMenuItemRect](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmenuitemrect): popup rectangles are meaningful only after display, and a null HWND resolves the popup menu window. The verifier waits for the displayed popup and independently rejects an input point belonging to another process.

Existing-user setup proof records user preferences separately from App lifecycle
bookkeeping. An older idle migration must preserve preferences and foreign files,
replace both old Obey commands, restart the idle daemon, and record matching setup
completion/update-check timestamps within the observed setup window. A current
installation and a normal reopen must preserve lifecycle timestamps as well as
receipts, executable mtimes, service PID and service unit. Raw settings observations
are retained even when validation fails. Public App inputs are fetched anonymously
once per workflow matrix and revalidated on each native runner before execution;
no authenticated API fallback is introduced.

The `missing-companion` existing-user scenario seeds the official current selected
profile with a recent background-check timestamp, then removes only the single
hash-verified receipt-owned `camp-app` command. The receipt and all other tools,
foreign files and user settings remain. Actual Installer status must report the
missing executable before launching the original published App. Acceptance
requires App-driven foreground repair to restore the exact official companion
file identity/version/capabilities, preserve every other selected package's
receipt/hash/mtime and the running Obey service PID/unit, then normal reopen with
an exact current no-op readback. Its explicit `missing_companion_repair_verified`
flag stays false on any native or cleanup failure. This is a missing-owned-file
case; it does not claim foreign-file overwrite, corrupt database recovery,
active-session continuity or licensed useful work.

The anonymous release metadata request honors explicit GitHub Retry-After and
exhausted-limit reset headers, with at most three retries and a one-hour reset
budget. Permission failures without rate-limit evidence, artifact failures,
invalid bytes and oversized inputs still fail immediately. Waits are logged;
there is no token fallback.

The fresh-only `verify_login_shell` option seeds a harmless foreign function in
the actual account's Bash login profile, actual Zsh startup directory, or
installed PowerShell7 CurrentUserAllHosts profile before App setup. It never preinstalls
selected packages or disables integration. After setup and normal App reopen,
ordinary interactive login Bash/Zsh shells run in an owned pty; PowerShell7 starts
with its normal profile loading and reports its actual runtime version. Each required camp/fest/obey/ob/camp-app command
must resolve to its actual managed executable and report the expected version,
and the foreign function/prefix must survive. Original terminal bytes, including
ANSI, are retained. Profile bytes/mtime and command results must remain unchanged
on reopen. The bundled Installer is used through the App; this does not require
a standalone managed festival hub. This default case does not cover stock Windows
PowerShell5.1; use the separate [explicit ordinary account shell](#explicit-ordinary-account-shells)
case below for that runtime. Neither shell case establishes cmd,
provider-wrapper/Windows Terminal UI, licensed work, login/reboot service recovery
or customer security prompts. The
explicit new_login_shell_verified flag stays false on any failure or cleanup
error. Existing seeded-user modes refuse this option.

Ordinary shell verification authenticates Camp/Fest's intended navigation
functions against the same installed binaries' generated shell-init definitions,
while separately checking the effective external executable and still executing
the ordinary wrapped command. Unknown same-version functions, aliases, cached
foreign commands and wrong external file identities fail. POSIX reference shells
have an isolated HOME/startup context; the actual login environment is unchanged.
Real Bash and Zsh tests run in the contracts Docker image.

The installed PowerShell7 proof uses hash-pinned PyWinpty 3.1.0's native WinPTY API
backend with explicit 120x40 dimensions (the bundled DLL/agent hashes and actual
loaded DLL path are retained). Only `pwsh -NoLogo` is used for startup, without
noninteractive/encoded startup or the Installer readiness override. A native identity handshake proves
ConsoleHost, unredirected input, ordinary startup flags and an owned process tree
before any command readback. Raw terminal bytes remain unmodified; structured
readback is separate. Owned PID/birth snapshots are retained before and during
execution, and cleanup verifies tracked descendants even after an adapter exits.
Disposable Windows CI must prove positive ordinary startup, timeout cleanup and
premature-adapter cleanup before this transport can qualify an App journey.
The separate `windows-powershell` selector exercises stock Windows PowerShell5.1
through the same qualified transport. cmd, Windows Terminal UI and consumer policy
remain outside these shell cases.


Login readback compares the complete validated camp-app version envelope except
its canonical per-call UUIDv7 requestId. Schema, outcome, build, version, protocol
and capabilities remain required and retained; raw output still contains the
original request identity. Other commands retain their complete version text.
POSIX function definitions are encoded by the verifier's absolute isolated Python
before crossing the PTY, then strictly decoded and compared byte-for-byte against
the installed binary's generated definition. This preserves literal source CR
bytes while avoiding terminal CR/LF ambiguity. PowerShell version probes use a
variable-array splat so functions receive ordinary string arguments; the native
console control asserts that same invocation contract.

A Linux window timeout now retains bounded read-only per-window Map State and WM
properties plus root window-manager properties and a post-probe PID/birth check.
These X queries never map a window or change rendering settings.
After the original failure and a successful App PID/birth recheck, the fresh
Linux workflow also records a native GDB stack. Attaching briefly pauses the
owned App; a bounded debugger process detaches afterward. Init scripts, automatic
binary scripts, remote debuginfo, locals and argument values are disabled. The
record retains debugger errors and post-attach process identity/state/tracer
checks. Native isolated fixtures exercise normal detach and debugger timeout,
including a heartbeat proving that the child resumes. None of this changes the
original launch failure to success or counts as useful first-use evidence.

The debugger runs with the owned App's UID/GID so it can read user-owned FUSE
mounts. Its only inherited, ambient, effective and bounding capability is
SYS_PTRACE; the original elevated timeout remains outside that restricted child.
The actual debugger reports those identities for verification. No file capability,
FUSE allow-other option or system ptrace policy is changed. A disposable FUSE
fixture proves root cannot read the mounted executable, while the same-UID
debugger obtains a symbolized stack and detaches. Only that fixture container
receives mount permissions; normal App verification retains its existing policy.

macOS query and normal-quit helpers are compiled once after artifact/sidecar
checks and before launching the App. Every capture executes the prepared native
helper, with no `swift -e` fallback. Build evidence records compiler invocation
and resolved identity, source/binary hashes and bounded preparation separately
from App startup; helper hashes are checked again before use. The `swiftc` alias
is preserved because resolving it to `swift-frontend` changes driver behavior.
Disposable ARM/Intel native controls require a real owned window, PID filtering,
wrong-bundle refusal without termination, a retained screenshot, and normal quit.
The fresh workflow also permits `intel` or `appimage` diagnostic replay while
keeping `all` as the unchanged full matrix and validating complete public inputs.

Linux native verification subscribes to root-child X11 lifecycle notifications
on its owned display before starting Openbox or the App. The flushed JSONL trace
records create/map/unmap/reparent/destroy/configure events, with readiness only
after the server acknowledges subscription. It selects nonexclusive notification
events, never window-manager redirection, and collects no input or window content.
After a child is reparented away from the root, its subsequent lifecycle is outside
this trace's scope. Observer errors, bounded truncation, and forced cleanup remain
diagnostic evidence and cannot turn an App failure into success. An isolated real
X11 fixture checks ordered lifecycle events, simultaneous manager subscription,
unavailable-display refusal, and cleanup of an unresponsive observer.

The fresh Linux desktop must be ready before launching the App. The verifier
waits for its live Openbox child's stable process birth, root/check-window EWMH
self-reference and Openbox name, and selected root SubstructureRedirect events.
This prevents launching into a bare display while the manager is still starting
and reparenting existing windows. Openbox omits `_NET_WM_PID`; no such attribution
is invented. Ownership comes from the unique empty X server and the single
manager launched by this proof. A real isolated control rejects a bare display
and an exited manager, then captures a managed window through the unchanged
App screenshot path. This establishes the harness precondition, not App readiness.

### Missing Git: manual restoration and real App Retry

The fresh workflow supports `platform_scope=deb` with
`verify_missing_git_manual=true` (unseeded, login proof disabled). Before changing
package state it creates local rollback packages for the observed Git dependency
closure (Git, git-lfs, git-ftp, gh and ubuntu-server only), refuses unrelated
removals, and verifies the
bundled Installer reports Git absent. The original App must expose its enabled
**Install Git and continue** button in the owned accessibility application.
After exact manual package/hash restoration, the verifier invokes that real
AT-SPI action once, then requires normal App-driven setup, service readback,
quit/reopen and owned cleanup. Original package plans, cached payload hashes,
prerequisite statuses and GitMissing screenshots remain in the proof.

This mode starts an owned session bus and enables the account's normal desktop
accessibility setting, restoring its previous value during cleanup. It does not
inject JavaScript or App commands, alter renderer security, replace Git on PATH,
or provide authorization credentials. `missing_git_manual_recovery_verified`
requires successful final cleanup. `automatic_git_authorization_verified` stays
false: a real desktop polkit authentication-agent/administrator prompt remains a
separate required journey; manual restoration cannot qualify that path.

Automation runs a real GTK button callback with foreign/stale/duplicate control
refusal and actual Git removal/restoration in disposable Docker. The package
fixture uses `fakeroot -u dpkg-repack --tag=none` with no runtime network: hosted
images remove the vendor repositories and archive caches for their preinstalled
versions. These are reconstructed local baseline backups, not original vendor
release archives. Every archive member is checked against installed bytes,
mode, UID/GID and symlink target before removal; missing or unsupported members
fail closed. Exact package file state, all installed package versions, and Git
system/user configuration hashes (including absence) must match after restore.
Extended attributes on a directory are allowed only when dpkg identifies an
installed owner outside the removal set. That shared directory remains in place;
its owner set and attribute hashes must match before removal and after restore.
Archives do not carry or restore those attributes. Attributes on files, symlinks
or directories without a retained owner remain unsupported and are refused.
Git LFS maintainer scripts can recreate the four default filter entries in a
different order. A private original system-config backup restores exact bytes
or original absence only when that known block is the sole change. The fixed-path
root helper checks the backup, current file digest and identity, permissions and
ownership; symlinks, hardlinks, custom LFS content and unrelated configuration
changes are refused. Original config contents are never included in artifacts.
Hardlink inode numbers and timestamps are not acceptance claims.
Both fixtures run as a normal account. Only real package mutations use sudo;
rollback archives remain owned by the verifier and final temporary cleanup is
verified. This does not prove the native App recovery or automatic Git download.
The isolated test image's fixture-only sudo configuration simulates the hosted
account; no host sudo or authentication policy is changed.


### Explicit ordinary account shells

The fresh workflow's `login_shell` input defaults to `default`, preserving the
existing full matrix and actual account Bash/Zsh or installed PowerShell7 path.
Nondefault choices require `verify_login_shell=true`, no existing-user seed and
no missing-Git mode; invalid platform/scope combinations fail before input fetch.

`windows-powershell` with `platform_scope=windows` selects the stock
`SystemRoot/System32/WindowsPowerShell/v1.0/powershell.exe`, verifies its actual
5.1 runtime and queries its own CurrentUserAllHosts profile. The ordinary prompt
still uses the existing native WinPTY transport and only `-NoLogo`, without
profile suppression, noninteractive startup or execution-policy changes. The
Windows native control runs positive argv/EOF/exit, timeout and intentional
adapter-death controls for both installed PowerShell7 and stock5.1. Microsoft
documents these startup options in [about PowerShell.exe](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1).

`zsh` with `platform_scope=mac` (both architectures) or `intel` selects actual
`/bin/zsh` for the disposable macOS account before the App launches. The fixture
checks Directory Services UID/home, permitted system shell and exact original
value; it changes only that account's UserShell and matching child environment,
then requires the real passwd/profile/login path. Cleanup restores the original
account and environment, refuses unexpected foreign changes, and cannot qualify
a run if restoration fails. Both Mac CI jobs separately exercise real account
selection, interactive login and restoration, including a failure after an
actual Directory Services write. That mutation control requires a non-Zsh
baseline and fails explicitly if it cannot exercise the write; the product
already-Zsh no-op branch has separate mocked contracts. These helper controls do
not establish App setup or required-tool availability.

Selected-shell App acceptance still requires original public payload checks,
App-driven provisioning, all five ordinary command/version/wrapper readbacks,
foreign profile preservation, unchanged state after normal reopen, real service
readback and complete cleanup. `new_login_shell_verified` stays false until the
whole native journey succeeds. These hosted-machine cases do not prove cmd,
Windows Terminal UI, consumer trust prompts, reboot or licensed useful work.

### Corrupt integration preferences: diagnosis and manual recovery

`existing_user=corrupt-integrations` requires `platform_scope=windows`, default
shell, no login proof and no missing-Git mode. It seeds the same genuine current
public selected packages and installed service as the current-user journey. The
fixture privately backs up its own valid `integrations.json`, refuses links,
hardlinks and foreign ownership, then adds an invalid JSON prefix. The bundled
Installer's real integration check must report that corruption; the original
packaged App must visibly show its configuration failure and diagnostic. The
original corrupt bytes, selected receipts/executable hashes/mtimes, service
PID/unit, settings, registered camp and foreign files must remain unchanged.

Only after normal App quit does the fixture restore its digest- and identity-bound
original preference bytes and mtime. Normal reopen must reach Licenses with
unchanged receipts/tools/service and user state, followed by another unchanged
reopen and complete owned cleanup. The private rollback file is not uploaded.
`corrupt_integration_manual_recovery_verified` remains false until every step and
cleanup passes. This proves an explicit manual support recovery on a disposable
account, not automatic Installer repair, receipt-database repair, arbitrary
foreign-file replacement, reboot, consumer trust or useful licensed work.

## Clean Linux guest infrastructure

`verify-linux-clean-vm.yml` first qualifies actual hardware virtualization on a
native disposable Ubuntu24.04 runner. It uses the existing `kvm` group only for
an ordinary-UID child, verifies KVM API12, creates an owned VM/vCPU and confirms
all descriptors close. It never changes device permissions, adds permanent group
membership, starts a root VM, or substitutes CPU emulation. The original JSON
report is retained even on failure.

The KVM preflight is infrastructure evidence only. It does not boot a guest or establish a
clean desktop, App installation, missing-Git recovery, licensing or reboot. Those
require an authenticated OS image, an isolated baseline and the actual published
App journey. Existing hosted developer images remain explicitly distinct from
clean consumer machines.

The clean-guest job extends that check with a pinned Canonical Ubuntu24.04 image
and cloud signing key. It verifies the detached checksum signature and exact
image digest before QEMU boots. A private seed provisions Xfce/LightDM and a
normal user whose sudo requires a random fixture password. Git and ecosystem
commands/state must be absent. All host control is localhost-only, SSH pins the
fixture's guest host key, and no host directories are shared.

After normal shutdown it cold-boots a separate disk/firmware clone, reboots that
clone and checks changed boot IDs, unchanged packages and an untouched baseline.
Original desktop screenshots and readbacks are retained; keys, passwords, seed,
disks and provisioning logs are never uploaded. This is a documented cloud-image
plus desktop fixture, not an unmodified retail OS installation. The clone logs in
through LightDM's actual password field before and after reboot. Readback
requires an active local logind X11 session, its real Xfce process/environment,
Xfwm4 window manager and existing owned user bus. It does not enable autologin or
replace the desktop with Xvfb. Public App installation/use, authorization dialogs
and service recovery after App installation still require their separate journeys.

The clean Linux workflow also accepts paired `app_source` / `app_version` inputs
for the unchanged public App test release. It installs observation utilities on
the disposable clone, rechecks that Git and ecosystem state are absent, and runs
the existing App verifier as a real Xfce autostart child. The Deb uses ordinary
password sudo. Missing Git follows automatic initial App setup or its existing
Retry control, then the normal polkit password dialog bound to the App-descended
apt request and owned OS authentication agent. Fixture passwords stay private and never enter App
arguments or environment. No authorization policy or passwordless sudo is added.

That optional journey retains the installed App and user service across a real
VM reboot and local login, then checks service response before reopening the App,
selected receipts/file mtimes and persisted settings. The enclosing VM is the
cleanup boundary; this mode does not claim App/service uninstallation. Original
screens and readbacks still require review. It does not grant a license, prove
useful first work or establish macOS/Windows consumer trust.

### Foreign companion: preserve and recover the original selected command

`existing_user=foreign-companion` is Windows-only with default shell, no login
proof and no missing-Git mode. It starts with the same current public selected
packages and responsive service. The fixture verifies the owned camp-app receipt,
privately backs up its exact original file, then substitutes the authenticated
candidate's genuine bundled Installer at that path. This is explicit fixture
preparation, not a new companion release, forged version or provider emulator.
The Installer's real `version --json` parser refuses the incompatible invocation;
the selected-plugin update must report `unmanaged`/`E_PLUGIN_FOREIGN` without
adopting or replacing it.

The original App must visibly explain the failed required-companion check and
its existing-owner remedy. While that error is present, the foreign bytes/mtime,
original receipt metadata, other selected files, service PID/unit, settings,
registered camp and foreign user files must remain unchanged. After normal App
quit, only the authenticated private original may be restored; unknown target or
backup changes refuse rollback. Two normal recovered launches must retain exact
current receipts/files and the original companion bytes/mtime. Cleanup is required
before `foreign_companion_manual_recovery_verified` can pass. This is bounded
preservation and explicit manual recovery, not automatic foreign-file adoption,
arbitrary uninstall, other-OS acceptance, consumer trust or useful licensed work.

### Receipt corruption fixture qualification

Automation CI also exercises a real Windows SQLite database, descriptor-bound
byte/mtime restoration, and refusal to restore while an owned Installer-name
process remains alive. Fixture executables and receipts are synthetic and never
establish production package or App recovery. The helper requires no App or
Installer process and no SQLite sidecars before backup, corruption or restoration.
Its initial immutable read explicitly asserts this already-verified quiescence;
normal live receipt readback keeps its existing read-only behavior. Recovered
readback may record a zero-byte WAL and ephemeral shared index without removing
them; any WAL transaction bytes remain a refusal. Packaged App corruption/retry
acceptance requires a separate original native journey.

### Packaged unreadable receipt-state manual recovery

`verify-app-fresh-setup.yml` accepts `existing_user=corrupt-receipts` only with
Windows or Debian scope, the default shell, and login/Git proof disabled. macOS
and AppImage receipt recovery are not supported by this verifier. Use a separately
qualified signed public candidate containing the App unreadable-state guard
(source `8b19ce6ffe2f2e747dd6b2ab2d78ee34869d3ef0` or reviewed successor).
The older B3 candidate does not establish this behavior.

The existing current-user seed supplies genuine selected packages and a service.
The fixture requires a closed, validated database with no WAL/SHM/journal before
its private backup and header corruption. The actual Installer must retain healthy
live tool facts while reporting incomplete receipt state. The App must show the
authenticated `E_INSTALLER_STATE_UNREADABLE` failure and recovery guidance while
all selected executable hashes/mtimes, existing settings, camp registration,
service identity and corrupted database bytes remain unchanged.

On Debian, a bounded AT-SPI observer reads visible text from the exact App PID,
process birth and executable, with identity checks before and after observation.
The original window screenshot is retained alongside the authenticated text;
the diagnostic must include the unreadable-state error and truthful unknown
installed-version presentation. The desktop accessibility setting is read before
enabling observation and restored with readback during cleanup, including failures.
Automation exercises the observer against a real GTK window, excludes hidden and
foreign text, and rejects stale process identity and unqualified invocation. These
controls alone do not establish packaged App recovery; that needs a separate
native public-candidate run with the complete preservation/readback checks.

Only after normal App quit and an actual no-App/no-Installer check can the fixture
restore its known private backup byte-for-byte and restore the original mtime on
a verified held handle. Two healthy launches and complete existing-user readbacks
must then pass. `corrupt_receipt_manual_recovery_verified` stays false on any
execution or cleanup failure. This is a controlled manual-backup/relaunch journey,
not automatic database repair, an in-place Retry-button proof or a claim that
customers already possess such a backup. Useful work, licensing, trust, reboot
and broad failure recovery remain separate.

The clean Linux VM workflow also accepts `app_package=appimage` with the immutable
public App source/version. Each run starts a separate clean clone without a Debian
App installation. The original authenticated download remains executable in the
guest through actual reboot; temporary extraction supplies only bundled CLI
observers. The App always launches from the original image. Before the reboot
launch, public inventory/digests and the production signature are checked again.
After launch/normal quit the retained public bytes must still match.

This mode requires the App's automatic, descendant Git installation request and
the ordinary OS password dialog. It cannot substitute the Deb Retry helper,
extracted AppRun, a rendering override or preinstalled ecosystem tools. The same
service-before-App, selected receipt/mtime and persisted setting checks apply
after reboot. A successful run still requires original screen and state review;
licensing, useful work and other-platform acceptance remain separate.


### Birth-valid Windows process ownership

Read-only process snapshots bind the root to its known creation time and check
every parent-to-child birth edge. Windows can retain a historical parent PID
after that PID has been reused; a process older than its apparent current parent
is excluded, even if it is newer than the root. Selected live process handles and
fresh CIM parent/birth tuples are revalidated before returning the original flat
PID/birth records. Unknown or changed identities fail closed; cleanup readback
still fails while any authenticated generation survives.

Native Windows controls exercise a real three-level tree, modeled historical PID
collisions both before the root and between root/child births, stale roots,
unknown births, live-survivor refusal and unrelated process survival. Original
40082723078 remains a failed cleanup-readback run; this repair does not waive it.
Microsoft documents the [ParentProcessId reuse/CreationDate contract](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-process)
and [held process handle lifetime](https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers).

### Existing external Festival suite compatibility

The fresh setup workflow has three explicit Debian-only `existing_user` cases:
`external-suite-old`, `external-suite-minimum`, and `external-suite-current`.
They require `platform_scope=deb`, default shell, no login-shell proof and no Git
recovery mode. Defaults and the ordinary full matrix are unchanged.

The fixture verifies pinned public Suite0.3.9/0.3.10/0.3.24 Debian bytes against
release checksums, installs the genuine package, provisions only the other two
selected CLI packages, and establishes normal service/terminal readiness. It
refuses any prior App settings and never seeds a background-check timestamp. The
actual first App launch therefore exercises the ready-existing-user background
path rather than suppressing it through a throttle fixture. Persisted readback requires
an actual completed release-check timestamp inside the observed launch window.
Minimum/current cases must still have no setup-completion timestamp, proving the
App did not mask the background path through successful foreground setup. The old
case instead requires matching foreground setup/check timestamps.

Old0.3.9 must receive a compatible managed suite while the three original package
executables remain exact. Minimum/current copies must stay resolved from
`/usr/bin`, with no managed suite receipt or shadow executables. An explicit
external readback validates the two remaining managed receipts; default validators
still require the normal three managed packages. Both launches must retain exact
receipts, files, external package identity, foreign data and responsive service.
The fixture removes only its authenticated, still-matching external package after
owned App/service teardown. Changed or replaced package state fails cleanup.

`external_suite_compatibility_verified` is separate from fresh-machine, useful
work, licensing, reboot and consumer trust. Source/tests and fixture setup do not
establish packaged acceptance: retain original App screens, public candidate
hashes/signatures, both real readbacks and cleanup before accepting a run.

### Real active-session update and deferred restart

The explicit Debian-only `existing_user=older-active` scenario requires default
shell, `platform_scope=deb`, no login-shell proof and no Git-recovery mode.
It retains the original idle migration fixture unchanged. Historical public
Obey0.2.2 bytes and the explicit receipt preparation are recorded separately
from the App's actual update to0.2.3.

A task-owned Ollama0.40.10 CPU runtime and checksum-pinned smollm2:135m model run
on the disposable machine's loopback interface with private provider home/model
directories. No operator endpoint, model store or credentials are used. Ollama
is test infrastructure, not an additional required App package. The runtime
archive is pinned by hash and size and only its CPU libraries are extracted.
The provider's normal shutdown is verified after owned App/service teardown.

Before App launch, a real registered camp/session must complete a durable provider
turn. After the App replaces both Obey commands, its persisted restart flag must
remain pending while the original process birth identity and executable hash
remain unchanged. Another turn must complete in the same running session without
changing the first turn. Other selected receipts/files, preferences, provider
configuration and the service definition must remain preserved. Obey's supported
deferred install refreshes the unit file; its new mtime is recorded rather than
mistaken for a daemon restart.

The verifier quits the App normally, stops the session normally, then reopens the
App. The App must clear the pending restart and run a different process using the
new authenticated executable bytes. Both prior durable turns must remain intact,
and a new session must complete a provider turn on that new daemon. Original App
screens and sanitized state reports are retained. Generated provider text and
the real-provider daemon log are not exported.

`active_session_update_verified` is independent of licensed useful App work,
consumer trust, reboot and other-platform acceptance. Source/unit checks or a
provider-only container run cannot establish this native published-App result.
