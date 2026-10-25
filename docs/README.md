# Maintaining Obedience releases

Start with the task you need to perform:

| Task | Guide |
| --- | --- |
| Understand tags, assets and their consumers | [Release contracts](release-contracts.md) |
| Choose a verification workflow | [Verification](verification.md) |
| Build or publish a new release | Use the owning producer's release workflow/runbook; this repository does not build the applications |
| Investigate a past native test | Follow its original Actions run and the historical record linked below |

Public downloads live here. Builds and publication live in the private
[Obey](https://github.com/Obedience-Corp/obey),
[Festival App](https://github.com/Obedience-Corp/festival-app), and
[Camp App](https://github.com/Obedience-Corp/camp-app) repositories; those links
require source access. The public
[Festival Installer](https://github.com/Obedience-Corp/festival-installer) and
[marketplace](https://github.com/Obedience-Corp/marketplace) own package installation
and discovery.

## Cleanup in progress

The target is public downloads plus bounded release verification. Some workflows
currently also run full product journeys. Keep those paths until replacements
in the private integration lab pass; do not infer completed migration from this
documentation change.

Maintainers can find the design under camp workitem `WI-9e8afa`, and current
product acceptance under `FA0027`. Historical investigation details remain in the
[README at the audited revision](https://github.com/Obedience-Corp/obey-releases/blob/e05bfffee078d4e5271623172a4c067e44720f78/README.md).
That is a historical reference, not a current release checklist.
