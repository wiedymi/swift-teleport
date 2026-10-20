#!/usr/bin/env python3
"""Run only a lab-owned browser and relay its authenticated loopback callback."""
import json
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.parse
import urllib.request

import lab


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def callback_url(value):
    if not isinstance(value, str) or len(value.encode()) > 1_000_000:
        raise lab.LabError('Invalid browser callback size.')
    url = urllib.parse.urlsplit(value)
    if (url.scheme != 'http' or url.hostname != '127.0.0.1' or
            url.username is not None or url.password is not None or
            url.path != '/callback' or url.fragment or url.port is None):
        raise lab.LabError('Invalid browser callback address.')
    query = urllib.parse.parse_qs(url.query, keep_blank_values=True)
    if set(query) != {'response'} or len(query['response']) != 1:
        raise lab.LabError('Invalid browser callback response.')
    return value


def run(fixture_path):
    fixture_path = Path(fixture_path).resolve()
    fixture = json.loads(fixture_path.read_text())
    instance = lab.Lab(fixture_path.parent.parent)
    if fixture.get('browserMFA') is not True:
        raise lab.LabError('The fixture does not enable browser MFA.')
    directory = instance.path / 'browser-mfa'
    request = directory / 'request.json'
    pending = directory / 'callback.json'
    completed = directory / 'callback-status.json'
    name = instance.path.name + '-browser-mfa-client'
    process = None
    try:
        for path in (pending, completed):
            path.unlink(missing_ok=True)
        process = subprocess.Popen(instance.command + [
            'run', '--rm', '--no-deps', '--name', name, 'browser-mfa'],
            env=instance.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 120
        while process.poll() is None and time.monotonic() < deadline:
            if pending.exists():
                if pending.stat().st_size > 1_000_000:
                    raise lab.LabError('Browser callback exceeds the test limit.')
                value = json.loads(pending.read_text())
                target = callback_url(value['url'])
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
                with opener.open(target, timeout=10) as response:
                    status = response.status
                lab.write_json(completed, {'status': status})
                pending.unlink()
            time.sleep(0.05)
        if process.poll() is None:
            raise lab.LabError('Browser MFA test exceeded its deadline.')
        if process.returncode != 0:
            raise lab.LabError('The browser MFA test failed; private browser output was suppressed.')
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        lab.execute(['docker', 'container', 'rm', '--force', name], env=instance.env, check=False)
        for path in (request, pending, pending.with_suffix('.json.tmp'), completed):
            path.unlink(missing_ok=True)


if __name__ == '__main__':
    def stop(_signal, _frame):
        raise lab.LabError('Browser MFA test canceled.')
    signal.signal(signal.SIGTERM, stop)
    try:
        if len(sys.argv) != 2:
            raise lab.LabError('One browser MFA fixture path is required.')
        run(sys.argv[1])
    except (lab.LabError, OSError, ValueError, KeyError):
        print('Browser MFA test failed. No authentication data was reported.', file=sys.stderr)
        sys.exit(1)
