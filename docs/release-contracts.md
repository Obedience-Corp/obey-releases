# Release contracts

These names are consumed by installers and updaters. Preserve them during repo
cleanup; change them only through the owning producer's release process.

| Product / record | Tags | Assets / consumer |
| --- | --- | --- |
| Obey | `v<version>` | Six `obey-<version>-<macOS\|linux\|windows>-<x86_64\|arm64>.tar.gz` archives and `checksums.txt`; Festival Installer resolves tags from the official marketplace entry |
| Camp App | `camp-app-v<version>` | Per-platform archives and checksums; signed marketplace package metadata records exact URLs and hashes |
| Festival App stable | `app-v<version>` | Desktop packages, update payloads and signatures; production feed is `app-stable/latest.json` |
| Festival App tests | `app-test-<full-source-sha>` | Immutable test packages and manifests; not the production update channel |
| Candidate drafts | `candidate-obey-*`, `candidate-app-*` | Unpublished binaries, hashes and identity manifests used before publication |
| Internal test drafts | `candidate-sessiondiscovery-*` | Historical internal observer-test inputs; not product downloads |

At the design audit, Obey `v0.2.3` and Camp App `camp-app-v0.1.0` were published.
Festival App had public test builds but no stable release/feed. Recheck live
state before updating that statement or recommending an installation.

Do not use the repository's generic latest-release URL to select an App or Camp
App version: multiple products share this repository. Keep each product's
existing version selection and feed convention.

The private producer workflows own publication. Draft candidate verification
does not publish or approve a release. Preserve original archives, checksum
names, signature keys, manifests and source identity when checking or migrating
verification code. Do not promote a test App build to fill a missing stable feed.

No release retention/deletion policy is introduced by cleanup. Check callers,
installed updater endpoints and retained evidence before proposing removal of
any draft or test release.
