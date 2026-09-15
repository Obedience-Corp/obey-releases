# obey releases

Release assets for the obey daemon and the ob client. This repository holds no source; it carries tags, GitHub releases, per-platform archives, and checksums.txt, published by the obey release workflow. The Festival installer resolves versions here with git ls-remote --tags and downloads assets from the release for the matching tag.

Archives: obey-<version>-<macOS|linux>-<x86_64|arm64>.tar.gz, each containing obey, ob, and LICENSE.
