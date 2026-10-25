# Obedience releases

Download Obedience software here. This repository hosts built applications and
checks their release packages. Application source code lives in separate private
repositories.

## Downloads

| Product | What it does | Download |
| --- | --- | --- |
| **Obey** | Runs local agent sessions. Each archive includes the `obey` daemon and `ob` command-line client. | [Obey releases](https://github.com/Obedience-Corp/obey-releases/releases?q=tag%3Av) |
| **Camp App** | Provides the command-line companion used by Festival App. | [Camp App releases](https://github.com/Obedience-Corp/obey-releases/releases?q=tag%3Acamp-app-v) |
| **Festival App** | The desktop application for working with your camps and agents. | [Festival App test builds](https://github.com/Obedience-Corp/obey-releases/releases?q=tag%3Aapp-test-) |

**Festival App currently has test builds only in this repository.** A stable App
release and its production update feed have not been published. Test builds are
labeled as prereleases; read their release notes before installing.

For command-line installation and updates, start with the
[Festival Installer](https://github.com/Obedience-Corp/festival-installer#readme).
For manual downloads, choose the asset matching your operating system and
processor. Release notes describe platform requirements; checksum files are
included with the downloads.

## Questions or problems?

[Open an issue](https://github.com/Obedience-Corp/obey-releases/issues) for a broken
download or release-package problem. Include the product, version and platform.

## Maintaining releases

Producer repositories build and publish the software. Verification workflows
here check the resulting binaries and packages. See the
[maintainer guide](docs/README.md) for release naming, workflow ownership and
the ongoing separation of product acceptance tests.

## License

The binaries are proprietary. See the [license](LICENSE) and the license shipped
with each release.
