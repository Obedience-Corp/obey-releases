"""Verify real public Debian inputs without installing packages or running tools."""
import json
import os
from pathlib import Path
import sys
import tempfile

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('public Debian input qualification requires isolated Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from external_suite import SPECS, PACKAGE
from verify_selected_components import fetch, checked_bootstrap
from verify_candidate import command

results = []
with tempfile.TemporaryDirectory() as temporary:
    for scenario, (version, size, digest, camp, fest) in SPECS.items():
        name = f'obedience-festival_{version}_amd64.deb'
        base = f'https://github.com/Obedience-Corp/festival/releases/download/v{version}/'
        data = fetch(base + name)
        assert len(data) == size
        assert checked_bootstrap(data, fetch(base + 'checksums.txt'), name) == digest
        path = Path(temporary) / name
        path.write_bytes(data)
        fields = command(['/usr/bin/dpkg-deb', '-f', path, 'Package', 'Version', 'Architecture'], dict(os.environ))
        assert fields.splitlines() == [f'Package: {PACKAGE}', f'Version: {version}', 'Architecture: amd64'], fields
        results.append({'scenario': scenario, 'url': base + name, 'sha256': digest,
                        'bytes': size, 'actual_dpkg_fields': fields.splitlines(),
                        'installed': False, 'executed': False})
        path.unlink()
print(json.dumps({'anonymous_public_inputs_verified': True, 'cases': results}, indent=2))
