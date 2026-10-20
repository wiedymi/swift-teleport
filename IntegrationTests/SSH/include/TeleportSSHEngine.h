// SPDX-License-Identifier: BSD-3-Clause
#ifndef TELEPORT_SSH_ENGINE_H
#define TELEPORT_SSH_ENGINE_H

#include <stddef.h>
#include <stdint.h>

enum TeleportSSHResult {
    TELEPORT_SSH_OK = 0,
    TELEPORT_SSH_INPUT = 2,
    TELEPORT_SSH_SETUP = 3,
    TELEPORT_SSH_TIMEOUT = 4,
    TELEPORT_SSH_HANDSHAKE = 10,
    TELEPORT_SSH_HOST_TRUST = 11,
    TELEPORT_SSH_AUTH = 12,
    TELEPORT_SSH_CHANNEL = 13,
    TELEPORT_SSH_COMMAND = 14,
    TELEPORT_SSH_OUTPUT_LIMIT = 15,
    TELEPORT_SSH_SFTP = 16
};

enum TeleportSSHOperation {
    TELEPORT_SSH_EXEC = 0,
    TELEPORT_SSH_PTY_RESIZE = 1,
    TELEPORT_SSH_SFTP_ROUNDTRIP = 2
};

// Return 0 to accept. Return any nonzero value to reject.
typedef int (*TeleportSSHVerifyHost)(const unsigned char *certificate,
                                     size_t certificate_length,
                                     void *context);

struct TeleportSSHCommand {
    enum TeleportSSHOperation operation;
    const char *username;
    const char *user_certificate;
    size_t user_certificate_length;
    const char *private_key;
    size_t private_key_length;
    // PTY_RESIZE must install a WINCH trap, print <teleport-pty-ready> without
    // a newline, then wait. The trap reports the size and exits after resize.
    const char *command;
    // NULL requires host certificates. Plain algorithms are for the separate
    // local fixture test of user certificates with a plain host key.
    const char *host_key_algorithms;
    const char *sftp_path;
    const unsigned char *input;
    size_t input_length;
    uint32_t timeout_milliseconds;
    TeleportSSHVerifyHost verify_host;
    void *verify_context;
};

// Test-only adapter. Consumes fd on every return, including invalid input.
// The caller must supply a connected socket and a host verifier. No TCP dial,
// password fallback, shell process, or Teleport protocol exists in this adapter.
// This call blocks its thread. Call it from a dedicated test runner queue.
// The verifier runs after KEX and before user authentication. It receives the
// complete host-certificate blob. It must copy any bytes it needs after return.
enum TeleportSSHResult teleport_ssh_run_command(
    int fd, const struct TeleportSSHCommand *request,
    unsigned char *output, size_t output_capacity, size_t *output_length,
    int *exit_status, int *native_error);

#endif
