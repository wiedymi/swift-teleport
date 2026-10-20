#!/usr/bin/env python3
"""Copy only client fixture inputs into the ignored Apple smoke app config."""
import argparse
import base64
import json
import os
from pathlib import Path
import ssl

ROOT = Path(__file__).resolve().parents[2]

def read(path, limit):
    path = Path(path)
    if path.stat().st_size > limit:
        raise ValueError('Fixture input exceeds its size limit.')
    return path.read_text()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture', type=Path)
    args = parser.parse_args()
    manifest = json.loads(read(args.fixture, 1_048_576))
    if manifest.get('schemaVersion') != 1 or 'localCredentialsFile' not in manifest:
        raise ValueError('A version 1 fixture with completed local enrollment is required.')
    credentials = json.loads(read(manifest['localCredentialsFile'], 65_536))
    ca = ssl.PEM_cert_to_DER_cert(read(manifest['httpsCAFile'], 65_536))
    config = {key: manifest[key] for key in ('proxyURL', 'clusterName', 'serverVersion', 'nodes')}
    config['httpsCA'] = base64.b64encode(ca).decode('ascii')
    config['credentials'] = {key: credentials[key] for key in ('username', 'password', 'totpSeed')}
    output = ROOT / 'Examples' / 'AppleSmoke' / 'SmokeConfig.json'
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, 'w') as file:
        json.dump(config, file)
        file.write('\n')
    print(output)

if __name__ == '__main__':
    main()
