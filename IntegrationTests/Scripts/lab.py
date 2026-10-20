#!/usr/bin/env python3
"""Owns only disposable Teleport lab resources. No production client imports."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
DOCKER = ROOT / 'IntegrationTests' / 'Docker'
RUNS = ROOT / 'IntegrationTests' / '.runs'
LOCK = json.loads((DOCKER / 'versions.lock.json').read_text())
NODES = ('node-a', 'node-b', 'node-denied')
RUN_ID = re.compile(r'^teleport-e2e-[a-f0-9]{12}$')

class LabError(Exception):
    pass

def execute(args, *, env=None, timeout=120, stdin=None, check=True):
    try:
        result = subprocess.run([str(a) for a in args], input=stdin, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LabError('Command unavailable or exceeded its deadline: ' + str(args[0])) from error
    if check and result.returncode:
        # Do not print tool output: provisioning commands can contain secret material.
        raise LabError('Command failed: ' + str(args[0]) + ' (exit ' + str(result.returncode) + ')')
    return result

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)

def log(message):
    print(message, file=sys.stderr, flush=True)

def compose_command():
    if execute(['docker', 'compose', 'version'], check=False).returncode == 0:
        return ['docker', 'compose']
    if shutil.which('docker-compose'):
        return ['docker-compose']
    raise LabError('Docker Compose is required. Install its CLI plugin or docker-compose.')

def preflight(host=None):
    if hashlib.sha256((DOCKER / 'Dockerfile.node').read_bytes()).hexdigest() != LOCK['nodeDockerfileSHA256']:
        raise LabError('The node Dockerfile changed. Review its inputs and update versions.lock.json.')
    if not shutil.which('docker'):
        raise LabError('Docker is required. No lab or test was started.')
    if execute(['docker', 'info'], timeout=20, check=False).returncode:
        raise LabError('The selected Docker engine is unavailable. Start it and check the Docker context.')
    command = compose_command()
    platform = json.loads(execute(['docker', 'info', '--format', '{{json .}}']).stdout)
    arch = {'aarch64': 'arm64', 'x86_64': 'amd64'}.get(platform.get('Architecture'), platform.get('Architecture'))
    if 'linux/' + str(arch) not in LOCK['teleport']['platformDigests']:
        raise LabError('Only native linux/arm64 and linux/amd64 Docker engines are supported.')
    if not shutil.which('openssl'):
        raise LabError('OpenSSL is required to create the per-run HTTPS CA.')
    if host:
        try:
            addresses = {row[4][0] for row in socket.getaddrinfo(host, None)}
        except OSError as error:
            raise LabError('The proxy hostname must resolve to loopback on this host: ' + host) from error
        if not addresses or not addresses <= {'127.0.0.1', '::1'}:
            raise LabError('The proxy hostname must resolve only to loopback: ' + host)
    return command, arch

class Lab:
    def __init__(self, path):
        self.path = path.resolve()
        if self.path.parent != RUNS.resolve() or not RUN_ID.fullmatch(self.path.name):
            raise LabError('Invalid lab run ID.')
        self.owner = json.loads((self.path / 'owner.json').read_text())
        if self.owner.get('runID') != self.path.name or self.owner.get('schemaVersion') != 1:
            raise LabError('Run ownership file does not match.')
        self.env = os.environ.copy()
        self.env.update(json.loads((self.path / 'compose-env.json').read_text()))
        self.command = compose_command() + ['--project-name', self.path.name, '--file', str(DOCKER / 'compose.yaml')]

    @property
    def proxy_url(self):
        return 'https://' + self.env['PROXY_HOST'] + ':' + self.env['PROXY_PORT']

    def compose(self, *args, **kwargs):
        return execute(self.command + list(args), env=self.env, **kwargs)

    def auth(self, *args, **kwargs):
        return self.compose('exec', '-T', 'auth-proxy', '/usr/local/bin/tctl', '--config=/etc/teleport/teleport.yaml', *args, **kwargs)

    def prepare_images(self):
        for name in ('TELEPORT_IMAGE', 'DEBIAN_IMAGE'):
            reference = self.env[name]
            if execute(['docker', 'image', 'inspect', reference], env=self.env, check=False).returncode:
                log('Retrieving the pinned base image: ' + reference)
                result = execute(['docker', 'pull', reference], env=self.env, timeout=300, check=False)
                if result.returncode:
                    # These are public pinned inputs; keep provisioning output private.
                    log(result.stderr.decode(errors='replace')[-3000:])
                    raise LabError('The exact pinned base image is unavailable: ' + reference)

    def build(self, services, seconds):
        result = self.compose('build', *services, timeout=seconds, check=False)
        if result.returncode:
            log(result.stderr.decode(errors='replace')[-3000:])
            raise LabError('Pinned fixture image build failed: ' + ', '.join(services))

    def wait(self, callback, message, seconds=120):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = callback()
            if value:
                return value
            time.sleep(1)
        raise LabError(message + ' exceeded its deadline. Run `lab.sh status --run-id ' + self.path.name + '`.')

    def ready(self, service):
        result = self.compose('exec', '-T', service, '/usr/local/bin/teleport', 'debug', 'readyz', check=False, timeout=5)
        if result.returncode:
            return False
        if re.fullmatch(rb'ready \(PID:[0-9]+\)\s*', result.stdout):
            return True
        try:
            return json.loads(result.stdout).get('status') == 'ok'
        except (ValueError, AttributeError):
            return False

    def ping(self):
        context = ssl.create_default_context(cafile=str(self.path / 'client' / 'https-ca.pem'))
        # Explicit empty proxy map keeps test traffic out of any inherited HTTP proxy.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        try:
            with opener.open(self.proxy_url + '/webapi/ping', timeout=5) as response:
                ping = json.load(response)
        except Exception:
            return False
        if ping.get('server_version') != LOCK['teleport']['version']:
            raise LabError('The running Teleport patch does not match versions.lock.json.')
        proxy = ping.get('proxy', {})
        if proxy.get('tls_routing_enabled') is not True:
            raise LabError('The running proxy did not enable TLS multiplexing.')
        auth = ping.get('auth', {})
        if auth.get('type') != 'local' or auth.get('second_factor') != 'otp':
            raise LabError('The running cluster authentication policy does not match the fixture.')
        return ping

    def node_resources(self):
        result = self.auth('get', 'nodes', '--format=json', check=False)
        if result.returncode:
            return False
        try:
            rows = json.loads(result.stdout)
            if isinstance(rows, dict):
                rows = rows.get('items', [])
            found = {item['spec']['hostname']: item['metadata']['name'] for item in rows}
            return found if set(NODES) <= set(found) else False
        except (ValueError, KeyError, TypeError):
            return False

    def tsh(self, *args, **kwargs):
        return self.compose('exec', '-T', 'auth-proxy', '/usr/local/bin/tsh',
                            '--identity=/run/client/identity', '--proxy=' + self.proxy_url.removeprefix('https://'),
                            *args, **kwargs)

    def control(self):
        checks = []
        for node in ('node-a', 'node-b'):
            result = self.tsh('ssh', 'teleport-test@' + node, "printf '%s\\n' '" + node + "'; printf '%s\\n' control-stderr >&2", check=False)
            if result.returncode != 0 or result.stdout != (node + '\n').encode() or result.stderr != b'control-stderr\n':
                log('Official-client control exit=' + str(result.returncode) + '; stderr=' + result.stderr.decode(errors='replace')[-2000:])
                raise LabError('Official-client stdout/stderr/exit-status control failed on ' + node)
            if self.tsh('ssh', 'teleport-test@' + node, 'exit 23', check=False).returncode != 23:
                raise LabError('Official-client remote exit-status control failed on ' + node)
            checks.extend((node + ':stdout-stderr', node + ':exit-status'))
        pty = self.tsh('ssh', '--tty', 'teleport-test@node-a',
                       'test -t 0 && stty rows 37 cols 91 && stty size && '
                       'tmux -L teleport-e2e new-session -d -s e2e && tmux -L teleport-e2e kill-server')
        if pty.stdout != b'37 91\r\n' or pty.stderr:
            raise LabError('Official-client Unix PTY/tmux control failed.')
        checks.append('node-a:pty-tmux')
        denied_marker = '/tmp/teleport-denied-' + secrets.token_hex(6)
        result = self.tsh('ssh', 'teleport-test@node-denied', 'touch ' + denied_marker, check=False)
        if result.returncode == 0 or not re.search(b'access denied|not authorized|permission denied', result.stderr, re.I):
            raise LabError('Denied-node control did not report server authorization denial.')
        self.compose('exec', '-T', 'node-denied', '/bin/test', '!', '-e', denied_marker)
        checks.append('node-denied:authorization')
        for node in NODES:
            result = self.compose('exec', '-T', 'node-b', 'nc', '-z', '-w', '1', node, '3022', check=False)
            if result.returncode == 0:
                raise LabError('A node direct SSH listener is reachable: ' + node)
            listeners = self.compose('exec', '-T', node, 'ss', '-H', '-ltn').stdout
            if re.search(rb':3022\s', listeners):
                raise LabError('A node opened a direct SSH listener: ' + node)
        checks.append('nodes:no-direct-ssh')
        self.compose('stop', '--timeout', '10', 'node-a')
        try:
            result = self.tsh('ssh', 'teleport-test@node-a', 'printf should-not-run', timeout=30, check=False)
            if result.returncode == 0 or result.stdout:
                raise LabError('Node access survived reverse-tunnel loss.')
        except LabError as error:
            if 'deadline' not in str(error):
                raise
        finally:
            self.compose('start', 'node-a')
            self.wait(lambda: self.ready('node-a'), 'Restarted node readiness')
        checks.append('node-a:reverse-tunnel-loss')
        return checks

    def down(self):
        # Compose removes only objects carrying this unique project label.
        self.compose('down', '--volumes', '--remove-orphans', '--timeout', '10', timeout=90)
        # Some runtimes add project-owned helpers that Compose does not track.
        remaining = execute(['docker', 'ps', '--all', '--quiet', '--filter',
                             'label=com.docker.compose.project=' + self.path.name], env=self.env).stdout.split()
        if remaining:
            execute(['docker', 'container', 'rm', '--force', *[item.decode() for item in remaining]], env=self.env)
        shutil.rmtree(self.path)


def pick_port():
    ports = list(range(18443, 18544))
    secrets.SystemRandom().shuffle(ports)
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(('127.0.0.1', port))
            except OSError:
                continue
        return port
    raise LabError('No free proxy port in the bounded range 18443–18543.')


def create(host, enroll):
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', host):
        raise LabError('Invalid proxy hostname.')
    _, arch = preflight(host)
    RUNS.mkdir(exist_ok=True, mode=0o700)
    path = RUNS / ('teleport-e2e-' + uuid.uuid4().hex[:12])
    path.mkdir(mode=0o700)
    try:
        for name in ('pki', 'config', 'tokens', 'admin-export', 'client', 'enrollment'):
            (path / name).mkdir(mode=0o700)
        now = dt.datetime.now(dt.timezone.utc)
        port = pick_port()
        cluster = path.name
        write_json(path / 'owner.json', {'schemaVersion': 1, 'runID': path.name, 'createdAt': now.isoformat()})
        teleport_image = LOCK['teleport']['image'] + '@' + LOCK['teleport']['indexDigest']
        env = {'RUN_DIR': str(path), 'PROXY_HOST': host, 'PROXY_PORT': str(port),
               'TELEPORT_IMAGE': teleport_image, 'DEBIAN_IMAGE': LOCK['debian']['image'],
               'DEBIAN_SNAPSHOT': LOCK['debian']['snapshot'], 'NODE_IMAGE': 'teleport-e2e-node:' + LOCK['teleport']['version'],
               'ENROLLMENT_IMAGE': 'teleport-e2e-enrollment:' + LOCK['playwrightCore']}
        for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
            if key in os.environ:
                env[key] = os.environ[key]
        if 'DOCKER_HOST' not in env and 'DOCKER_CONTEXT' not in env:
            env['DOCKER_CONTEXT'] = execute(['docker', 'context', 'show']).stdout.decode().strip()
        write_json(path / 'compose-env.json', env)
        pki = path / 'pki'
        execute(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1', '-subj', '/CN=Teleport E2E HTTPS CA', '-keyout', pki / 'https-ca.key', '-out', pki / 'https-ca.pem'])
        execute(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + host, '-keyout', pki / 'proxy.key', '-out', pki / 'proxy.csr'])
        (pki / 'extensions.cnf').write_text('subjectAltName=DNS:' + host + '\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
        execute(['openssl', 'x509', '-req', '-in', pki / 'proxy.csr', '-CA', pki / 'https-ca.pem', '-CAkey', pki / 'https-ca.key', '-set_serial', str(secrets.randbits(128) or 1), '-days', '1', '-sha256', '-extfile', pki / 'extensions.cnf', '-out', pki / 'proxy.pem'])
        shutil.copyfile(pki / 'https-ca.pem', path / 'client' / 'https-ca.pem')
        shutil.copyfile(DOCKER / 'roles.yaml', path / 'roles.yaml')
        auth = {'version': 'v3', 'teleport': {'nodename': 'auth-proxy', 'data_dir': '/var/lib/teleport', 'log': {'severity': 'ERROR'}},
                'auth_service': {'enabled': True, 'cluster_name': cluster, 'proxy_listener_mode': 'multiplex', 'session_recording': 'node', 'authentication': {'type': 'local', 'second_factor': 'otp'}},
                'proxy_service': {'enabled': True, 'web_listen_addr': '0.0.0.0:' + str(port), 'public_addr': host + ':' + str(port), 'proxy_protocol': 'off', 'https_keypairs': [{'key_file': '/run/pki/proxy.key', 'cert_file': '/run/pki/proxy.pem'}]},
                'ssh_service': {'enabled': False}}
        write_json(path / 'config' / 'auth-proxy.json', auth)
        for node in NODES:
            config = {'version': 'v3', 'teleport': {'nodename': node, 'data_dir': '/var/lib/teleport', 'proxy_server': host + ':' + str(port), 'auth_token': '/run/join-token', 'log': {'severity': 'ERROR'}},
                      'auth_service': {'enabled': False}, 'proxy_service': {'enabled': False},
                      'ssh_service': {'enabled': True, 'force_listen': False, 'labels': {'e2e-access': 'denied' if node == 'node-denied' else 'allowed'}, 'enhanced_recording': {'enabled': False}, 'pam': {'enabled': False}}}
            write_json(path / 'config' / (node + '.json'), config)
        lab = Lab(path)
    except BaseException:
        shutil.rmtree(path)
        raise
    try:
        lab.prepare_images()
        log('Building pinned fixtures for ' + arch + '.')
        lab.build(('node-a', 'enrollment') if enroll else ('node-a',), 900 if enroll else 600)
        log('Starting Auth/Proxy with verified HTTPS trust.')
        # Retry only a demonstrated host-port collision; no unrelated failure fallback.
        for attempt in range(3):
            result = lab.compose('up', '--detach', 'auth-proxy', check=False, timeout=180)
            if result.returncode == 0:
                break
            if attempt == 2 or not re.search(rb'address already in use|port is already allocated', result.stderr, re.I):
                log(result.stderr.decode(errors='replace')[-3000:])
                raise LabError('Auth/Proxy start failed. No version fallback was attempted.')
            lab.compose('rm', '--force', '--stop', 'auth-proxy', check=False)
            port = pick_port()
            lab.env['PROXY_PORT'] = str(port)
            env['PROXY_PORT'] = str(port)
            write_json(path / 'compose-env.json', env)
            auth['proxy_service']['web_listen_addr'] = '0.0.0.0:' + str(port)
            auth['proxy_service']['public_addr'] = host + ':' + str(port)
            write_json(path / 'config' / 'auth-proxy.json', auth)
            for node in NODES:
                config_path = path / 'config' / (node + '.json')
                config = json.loads(config_path.read_text())
                config['teleport']['proxy_server'] = host + ':' + str(port)
                write_json(config_path, config)
        lab.wait(lambda: lab.ready('auth-proxy'), 'Auth/Proxy process readiness')
        lab.wait(lab.ping, 'Verified discovery')
        lab.auth('create', '/run/roles.yaml')
        invitation = lab.auth('users', 'add', 'e2e-user', '--roles=e2e-client', '--logins=teleport-test', '--ttl=15m').stdout.decode()
        match = re.search(r'/web/invite/([A-Za-z0-9_-]+)', invitation)
        if not match:
            raise LabError('The pinned tctl invitation output is unsupported.')
        write_json(path / 'enrollment' / 'invitation.json', {'username': 'e2e-user', 'token': match.group(1)})
        for node in NODES:
            token = lab.auth('tokens', 'add', '--type=node', '--ttl=10m', '--format=text').stdout.decode().strip()
            if not re.fullmatch(r'[a-zA-Z0-9_-]{16,256}', token):
                raise LabError('The pinned tctl node-token output is unsupported.')
            (path / 'tokens' / node).write_text(token)
        log('Starting three nodes through verified reverse tunnels.')
        lab.compose('up', '--detach', *NODES, timeout=120)
        for node in NODES:
            lab.wait(lambda name=node: lab.ready(name), node + ' process readiness')
        resources = lab.wait(lab.node_resources, 'Expected registered nodes')
        if enroll:
            log('Completing real browser password/TOTP enrollment with trusted HTTPS.')
            result = lab.compose('run', '--rm', '--no-deps', 'enrollment', timeout=90, check=False)
            if result.returncode:
                log(result.stderr.decode(errors='replace')[-2000:])
                raise LabError('Local browser enrollment failed.')
        lab.auth('auth', 'sign', '--user=e2e-user', '--format=file', '--ttl=30m', '--out=/run/admin-export/identity')
        shutil.copyfile(path / 'admin-export' / 'identity', path / 'client' / 'identity')
        log('Running the separate official-client infrastructure control.')
        checks = lab.control()
        manifest = {'schemaVersion': 1, 'proxyURL': lab.proxy_url, 'clusterName': cluster,
                    'serverVersion': LOCK['teleport']['version'], 'httpsCAFile': str(path / 'client' / 'https-ca.pem'),
                    'identityFile': str(path / 'client' / 'identity'),
                    'nodes': [{'name': name, 'id': resources[name], 'authorized': name != 'node-denied'} for name in NODES],
                    'policy': {'authentication': 'local', 'secondFactor': 'otp', 'tlsRouting': True}}
        if enroll:
            manifest['localCredentialsFile'] = str(path / 'client' / 'local-credentials.json')
        write_json(path / 'client' / 'fixture.json', manifest)
        version_output = lab.compose('exec', '-T', 'auth-proxy', '/usr/local/bin/teleport', 'version').stdout.decode().strip()
        write_json(path / 'report.json', {'schemaVersion': 1, 'runID': path.name, 'platform': 'linux/' + arch,
                   'serverVersion': LOCK['teleport']['version'], 'infrastructureControl': checks,
                   'localEnrollment': enroll, 'teleportVersionOutput': version_output})
        for file in path.rglob('*'):
            if file.is_file():
                file.chmod(0o600)
        return lab
    except BaseException:
        try:
            lab.down()
        except Exception:
            log('Automatic teardown failed. Use lab.sh down --run-id ' + path.name)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('up', 'status', 'down', 'clean-stale', 'control', 'preflight'))
    parser.add_argument('--run-id')
    parser.add_argument('--host', default='teleport.localhost')
    parser.add_argument('--without-enrollment', action='store_true', help='Transport-only fixture; report explicitly excludes local login.')
    args = parser.parse_args()
    os.umask(0o077)
    if args.operation == 'preflight':
        _, arch = preflight(args.host)
        print(json.dumps({'dockerPlatform': 'linux/' + arch, 'ready': True}))
        return
    if args.operation == 'up':
        lab = create(args.host, not args.without_enrollment)
        print(lab.path / 'client' / 'fixture.json')
        return
    if args.operation == 'clean-stale':
        for path in sorted(RUNS.glob('teleport-e2e-*')):
            lab = Lab(path)
            expiry = dt.datetime.fromisoformat(lab.owner['createdAt']) + dt.timedelta(hours=2)
            if expiry < dt.datetime.now(dt.timezone.utc):
                lab.down()
                print(path.name)
        return
    if not args.run_id or not RUN_ID.fullmatch(args.run_id):
        raise LabError('--run-id is required and must name a lab-owned run.')
    path = RUNS / args.run_id
    if args.operation == 'down' and not path.exists():
        return
    lab = Lab(path)
    if args.operation == 'down':
        lab.down()
    elif args.operation == 'control':
        print(json.dumps({'infrastructureControl': lab.control()}))
    else:
        raw = lab.compose('ps', '--all', '--format=json').stdout.decode().strip()
        rows = json.loads(raw) if raw.startswith('[') else [json.loads(line) for line in raw.splitlines()]
        print(json.dumps({'runID': path.name, 'services': [{'service': x['Service'], 'state': x['State'], 'health': x.get('Health')} for x in rows]}, indent=2))

if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        main()
    except (LabError, OSError, ValueError) as error:
        log(str(error))
        sys.exit(1)
    except KeyboardInterrupt:
        log('Lab command cancelled.')
        sys.exit(130)
