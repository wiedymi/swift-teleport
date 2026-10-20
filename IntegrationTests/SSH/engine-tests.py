#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Local engine tests. These tests do not establish Teleport compatibility."""

import argparse
import base64
import contextlib
import json
import os
import pathlib
import platform
import pwd
import selectors
import socket
import struct
import subprocess
import tempfile
import threading


def key(directory, name, algorithm, bits=None):
    path = directory / name
    command = ["ssh-keygen", "-q", "-t", algorithm, "-N", "", "-f", str(path)]
    if bits:
        command += ["-b", str(bits)]
    subprocess.run(command, check=True, capture_output=True)
    return path


def sign(ca, identity, key_path, principal, validity="-1m:+10m", host=False):
    command = ["ssh-keygen", "-q", "-s", str(ca), "-I", identity,
               "-n", principal, "-V", validity]
    if host:
        command += ["-h"]
    subprocess.run(command + [str(key_path) + ".pub"], check=True, capture_output=True)
    certificate = pathlib.Path(str(key_path) + "-cert.pub")
    blob = pathlib.Path(str(key_path) + ".blob")
    blob.write_bytes(base64.b64decode(certificate.read_text().split()[1], validate=True))
    return certificate, blob


@contextlib.contextmanager
def server(directory, host, user_ca, algorithm, with_certificate=True):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = directory / "sshd.conf"
    certificate_setting = f"HostCertificate {host}-cert.pub\n" if with_certificate else ""
    config.write_text(f"""Port {port}
ListenAddress 127.0.0.1
HostKey {host}
{certificate_setting}\
HostKeyAlgorithms {algorithm}
TrustedUserCAKeys {user_ca}.pub
AuthorizedKeysFile none
PidFile {directory}/sshd.pid
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
LogLevel ERROR
Subsystem sftp internal-sftp
""")
    # sshd logs the listening line at INFO level; use a pipe only for startup.
    command = ["/usr/sbin/sshd", "-D", "-e", "-o", "LogLevel=VERBOSE", "-f", str(config)]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stderr, selectors.EVENT_READ)
            if not selector.select(5):
                raise RuntimeError("sshd did not report readiness")
            line = process.stderr.readline()
            if b"Server listening" not in line:
                raise RuntimeError("sshd startup failed: " + line.decode(errors="replace"))
        # The matrix has few connections. The pipe remains well below its limit.
        yield port
    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


def receive_exact(connection, count):
    output = bytearray()
    while len(output) < count:
        data = connection.recv(count - len(output))
        if not data:
            raise EOFError()
        output.extend(data)
    return output


@contextlib.contextmanager
def changed_kex_signature(destination_port):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    connections = []
    threads = []
    changed = threading.Event()

    def forward(source, destination):
        try:
            while data := source.recv(65536):
                destination.sendall(data)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                destination.shutdown(socket.SHUT_WR)

    def run():
        try:
            client, _ = listener.accept()
            remote = socket.create_connection(("127.0.0.1", destination_port), timeout=5)
            connections.extend([client, remote])
            client.settimeout(5)
            upstream = threading.Thread(target=forward, args=(client, remote), daemon=True)
            threads.append(upstream)
            upstream.start()
            # Forward the server identification line before binary SSH packets.
            while True:
                line = bytearray()
                while not line.endswith(b"\n"):
                    line += receive_exact(remote, 1)
                    if len(line) > 1024:
                        raise ValueError("oversized SSH identification")
                client.sendall(line)
                if line.startswith(b"SSH-"):
                    break
            while not changed.is_set():
                header = receive_exact(remote, 4)
                packet_length = struct.unpack(">I", header)[0]
                if not 6 <= packet_length <= 262144:
                    raise ValueError("invalid clear SSH packet")
                body = receive_exact(remote, packet_length)
                # SSH_MSG_KEX_ECDH_REPLY: host key, ephemeral key, signature.
                if body[1] == 31:
                    offset = 2
                    for _ in range(2):
                        field_length = struct.unpack(">I", body[offset:offset + 4])[0]
                        offset += 4 + field_length
                    signature_length = struct.unpack(">I", body[offset:offset + 4])[0]
                    signature_end = offset + 4 + signature_length
                    if signature_length < 1 or signature_end > packet_length - body[0]:
                        raise ValueError("invalid SSH signature field")
                    body[signature_end - 1] ^= 1
                    changed.set()
                client.sendall(header + body)
            forward(remote, client)
        except (OSError, EOFError):
            pass

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    try:
        yield port, changed
    finally:
        listener.close()
        for connection in connections:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()
        worker.join(timeout=6)
        for thread in threads:
            thread.join(timeout=6)
        if worker.is_alive() or any(thread.is_alive() for thread in threads):
            raise RuntimeError("SSH test proxy did not stop")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stock", type=pathlib.Path, required=True)
    parser.add_argument("--patched", type=pathlib.Path, required=True)
    parser.add_argument("--import-test", type=pathlib.Path, required=True)
    parser.add_argument("--report", type=pathlib.Path)
    args = parser.parse_args()
    login = pwd.getpwuid(os.getuid()).pw_name
    rows = []

    def run(binary, port, host_blob, user, expected=0, command="printf teleport-engine-ok",
            plain=False, operation=None, expected_output=b"teleport-engine-ok", sftp_path=None):
        environment = dict(os.environ)
        environment.pop("TELEPORT_ENGINE_HOST_ALGORITHMS", None)
        environment.pop("TELEPORT_ENGINE_OPERATION", None)
        environment.pop("TELEPORT_ENGINE_SFTP_PATH", None)
        if plain:
            environment["TELEPORT_ENGINE_HOST_ALGORITHMS"] = "ssh-ed25519"
        if operation:
            environment["TELEPORT_ENGINE_OPERATION"] = operation
        if sftp_path:
            environment["TELEPORT_ENGINE_SFTP_PATH"] = str(sftp_path)
        result = subprocess.run([str(binary), str(port), login, str(host_blob),
                                 str(user) + "-cert.pub", str(user), command],
                                capture_output=True, timeout=20, env=environment)
        if result.returncode != expected or (expected == 0 and result.stdout != expected_output):
            raise AssertionError(f"engine result {result.returncode}, expected {expected}: "
                                 + result.stderr.decode(errors="replace"))
        return result.stderr.decode().strip()

    with tempfile.TemporaryDirectory(prefix="teleport-ssh-fixtures.") as temporary:
        directory = pathlib.Path(temporary)
        host_ca = key(directory, "host-ca", "ed25519")
        user_ca = key(directory, "user-ca", "ed25519")
        users = []
        for name, algorithm, bits in [("ed25519", "ed25519", None),
                                      ("ecdsa", "ecdsa", 256), ("rsa", "rsa", 2048)]:
            user = key(directory, "user-" + name, algorithm, bits)
            sign(user_ca, "engine-user", user, login)
            users.append((name, user))
        expired = key(directory, "expired", "ed25519")
        sign(user_ca, "expired-user", expired, login, "-10m:-5m")
        denied = key(directory, "denied", "ed25519")
        sign(user_ca, "denied-user", denied, "teleport-no-such-login")

        plain_host = key(directory, "plain-host", "ed25519")
        plain_blob = directory / "plain-host.blob"
        plain_blob.write_bytes(base64.b64decode(
            pathlib.Path(str(plain_host) + ".pub").read_text().split()[1], validate=True))
        with server(directory, plain_host, user_ca, "ssh-ed25519", False) as port:
            for user_name, user in users:
                rows.append({"check": "stock-user-certificate", "user": user_name,
                             "result": run(args.stock, port, plain_blob, user, plain=True)})

        hosts = [("ed25519", "ed25519", None, "ssh-ed25519-cert-v01@openssh.com")]
        hosts += [("ecdsa" + str(bits), "ecdsa", bits,
                   f"ecdsa-sha2-nistp{bits}-cert-v01@openssh.com") for bits in (256, 384, 521)]
        hosts += [("rsa", "rsa", 2048, "rsa-sha2-512-cert-v01@openssh.com")]
        for name, algorithm, bits, negotiated in hosts:
            host = key(directory, "host-" + name, algorithm, bits)
            _, host_blob = sign(host_ca, "engine-host", host, "test-node", host=True)
            imported = subprocess.run([str(args.import_test), str(host_blob)],
                                      capture_output=True, check=True, timeout=10)
            rows.append({"check": "malformed-host-import", "host": name,
                         "result": imported.stdout.decode().strip()})
            with server(directory, host, user_ca, negotiated) as port:
                rows.append({"check": "stock-host-certificate", "host": name,
                             "result": run(args.stock, port, host_blob, users[0][1], 10)})
                for user_name, user in users:
                    rows.append({"check": "patched-command", "host": name,
                                 "user": user_name,
                                 "result": run(args.patched, port, host_blob, user)})
                if name == "ed25519":
                    rows.append({"check": "pty-resize", "result":
                                 run(args.patched, port, host_blob, users[0][1],
                                     command="sh -c 'test \"$(stty size)\" = \"24 80\" || exit 99; "
                                             "trap \"stty size; exit\" WINCH; "
                                             "printf \"<teleport-pty-ready>\"; "
                                             "while :; do read -r ignored; done'", operation="pty",
                                     expected_output=b"43 121\r\n")})
                    remote_path = directory / "sftp-roundtrip"
                    rows.append({"check": "sftp-roundtrip", "result":
                                 run(args.patched, port, host_blob, users[0][1],
                                     operation="sftp", sftp_path=remote_path)})
                    if remote_path.exists():
                        raise AssertionError("SFTP test file was not removed")
                    rows.append({"check": "expired-user", "result":
                                 run(args.patched, port, host_blob, expired, 12)})
                    rows.append({"check": "denied-login", "result":
                                 run(args.patched, port, host_blob, denied, 12)})
                    wrong_host = directory / "wrong-host.blob"
                    wrong_host.write_bytes(host_blob.read_bytes() + b"\0")
                    rows.append({"check": "host-verifier-denial", "result":
                                 run(args.patched, port, wrong_host, users[0][1], 11)})
                    with changed_kex_signature(port) as (proxy_port, changed):
                        result = run(args.patched, proxy_port, host_blob, users[0][1], 10)
                        if not changed.is_set():
                            raise AssertionError("KEX signature test did not change a signature")
                        rows.append({"check": "changed-kex-signature", "result": result})

    report = {"system": platform.platform(), "sshd": subprocess.run(
        ["/usr/sbin/sshd", "-V"], capture_output=True).stderr.decode().strip(),
        "checks": rows}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Passed {len(rows)} local SSH engine checks; 15 host/user certificate pairs, 3 stock user-certificate checks.")


if __name__ == "__main__":
    main()
