// SPDX-License-Identifier: BSD-3-Clause
#include "TeleportSSHEngine.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int reject_host(const unsigned char *certificate, size_t length, void *context)
{
    (void)certificate; (void)length; (void)context;
    return 1;
}

static void rejects_and_closes(const struct TeleportSSHCommand *request)
{
    int pair[2], status, native_error;
    unsigned char output[8];
    size_t length;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(teleport_ssh_run_command(pair[0], request, output, sizeof(output),
                                   &length, &status, &native_error) == TELEPORT_SSH_INPUT);
    assert(fcntl(pair[0], F_GETFD) == -1 && errno == EBADF);
    assert(read(pair[1], output, sizeof(output)) == 0);
    close(pair[1]);
}

int main(void)
{
    char long_login[257], long_path[4098], long_command[65538];
    const struct TeleportSSHCommand valid = {
        .username = "test", .user_certificate = "certificate", .user_certificate_length = 11,
        .private_key = "key", .private_key_length = 3, .command = "true",
        .timeout_milliseconds = 10, .verify_host = reject_host
    };
    struct TeleportSSHCommand request;
    rejects_and_closes(NULL);
    request = valid; request.operation = (enum TeleportSSHOperation)99;
    rejects_and_closes(&request);
    request = valid; request.user_certificate_length = 350001;
    rejects_and_closes(&request);
    request = valid; request.private_key_length = 16385;
    rejects_and_closes(&request);
    memset(long_login, 'a', sizeof(long_login) - 1); long_login[sizeof(long_login) - 1] = 0;
    request = valid; request.username = long_login;
    rejects_and_closes(&request);
    memset(long_command, 'a', sizeof(long_command) - 1); long_command[sizeof(long_command) - 1] = 0;
    request = valid; request.command = long_command;
    rejects_and_closes(&request);
    memset(long_path, 'a', sizeof(long_path) - 1); long_path[sizeof(long_path) - 1] = 0;
    request = valid; request.operation = TELEPORT_SSH_SFTP_ROUNDTRIP;
    request.sftp_path = long_path; request.input = (const unsigned char *)"test"; request.input_length = 4;
    rejects_and_closes(&request);
    request = valid; request.operation = TELEPORT_SSH_SFTP_ROUNDTRIP;
    request.sftp_path = "/tmp/test"; request.input = (const unsigned char *)"test"; request.input_length = 9;
    rejects_and_closes(&request);
    puts("adapter_input_bounds_and_descriptor_cleanup=8 passed");
    return 0;
}
