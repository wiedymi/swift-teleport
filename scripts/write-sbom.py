#!/usr/bin/env python3
"""Write a source dependency inventory from the exact SwiftPM lock."""
import hashlib
import json
import pathlib

root = pathlib.Path(__file__).resolve().parents[1]
source = (root / 'Package.resolved').read_bytes()
pins = json.loads(source)['pins']
packages = []
for pin in pins:
    name = pin['identity']
    state = pin['state']
    packages.append({
        'SPDXID': 'SPDXRef-' + name,
        'name': name,
        'versionInfo': state['version'],
        'downloadLocation': 'git+' + pin['location'] + '@' + state['revision'],
        'filesAnalyzed': False,
        'licenseConcluded': 'NOASSERTION',
        'licenseDeclared': 'Apache-2.0 WITH Swift-exception' if name in ['swift-atomics', 'swift-collections', 'swift-system', 'swift-protobuf'] else 'Apache-2.0',
        'copyrightText': 'NOASSERTION',
        'externalRefs': [{'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl',
                          'referenceLocator': 'pkg:github/apple/' + name + '@' + state['version']}],
    })
document = {
    'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT',
    'name': 'TeleportKit source dependencies',
    'documentNamespace': 'https://github.com/wiedymi/swift-teleport/sbom/' + hashlib.sha256(source).hexdigest(),
    'creationInfo': {'created': '2026-10-20T00:00:00Z', 'creators': ['Tool: swift-teleport/scripts/write-sbom.py']},
    'packages': packages,
    'relationships': [{'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES', 'relatedSpdxElement': p['SPDXID']} for p in packages],
}
(root / 'docs/dependencies.spdx.json').write_text(json.dumps(document, indent=2) + '\n')
