# Official marketplace shape fixture

`official-marketplace-ebb0b7f.json` is the exact public Git blob
`ebb0b7f3054f2bd38cf4918da9bd1b1c0ba15011` from
https://github.com/Obedience-Corp/marketplace/blob/main/obey-marketplace.json.
The test checks its Git blob ID rather than depending on that moving branch.
It covers manifest-backed Festival/Camp App and release-source-backed Obey.

This is catalog-shape and byte-retention evidence, not signature validation.
The test supplies an explicitly synthetic signature. Native acceptance uses the
unmodified released Installer's signature/checksum policy and checks installed
versions and physical files against its receipts; the report preserves those
receipts and actual catalog bytes/signatures before App launch.
