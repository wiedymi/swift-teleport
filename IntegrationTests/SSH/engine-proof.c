// SPDX-License-Identifier: BSD-3-Clause
#include "TeleportSSHEngine.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <libssh2.h>

struct Bytes { unsigned char *data; size_t length; };

static struct Bytes read_fixture(const char *path)
{
    struct Bytes bytes = { NULL, 0 };
    FILE *file = fopen(path, "rb");
    long length;
    if(!file || fseek(file, 0, SEEK_END) != 0 ||
       (length = ftell(file)) <= 0 || length > 1024 * 1024 ||
       fseek(file, 0, SEEK_SET) != 0) {
        if(file) fclose(file);
        return bytes;
    }
    bytes.data = malloc((size_t)length);
    if(bytes.data && fread(bytes.data, 1, (size_t)length, file) == (size_t)length)
        bytes.length = (size_t)length;
    else {
        free(bytes.data);
        bytes.data = NULL;
    }
    fclose(file);
    return bytes;
}

static int compare_host(const unsigned char *blob, size_t length, void *context)
{
    const struct Bytes *expected = context;
    // Fixture-only exact comparison. The public API harness supplies the
    // TeleportCore CA verifier here, before any user authentication occurs.
    return expected->length != length || memcmp(expected->data, blob, length);
}

int main(int argc, char **argv)
{
    struct sockaddr_in address;
    struct Bytes expected, certificate, private_key;
    unsigned char output[65536];
    size_t output_length = 0;
    int fd, exit_status, native_error;
    enum TeleportSSHResult result;
    char *end;
    long port;
    struct TeleportSSHCommand request;
    const char *operation = getenv("TELEPORT_ENGINE_OPERATION");

    if(argc != 7) {
        fprintf(stderr, "usage: engine-proof PORT LOGIN HOST_BLOB USER_CERT KEY COMMAND\n");
        return TELEPORT_SSH_INPUT;
    }
    errno = 0;
    port = strtol(argv[1], &end, 10);
    if(errno || *end || port < 1 || port > 65535)
        return TELEPORT_SSH_INPUT;
    expected = read_fixture(argv[3]);
    certificate = read_fixture(argv[4]);
    private_key = read_fixture(argv[5]);
    if(!expected.data || !certificate.data || !private_key.data) {
        free(expected.data); free(certificate.data); free(private_key.data);
        return TELEPORT_SSH_INPUT;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        if(fd >= 0) close(fd);
        free(expected.data); free(certificate.data); free(private_key.data);
        return TELEPORT_SSH_SETUP;
    }
    request = (struct TeleportSSHCommand) {
        .operation = operation && strcmp(operation, "pty") == 0 ?
            TELEPORT_SSH_PTY_RESIZE : operation && strcmp(operation, "sftp") == 0 ?
            TELEPORT_SSH_SFTP_ROUNDTRIP : TELEPORT_SSH_EXEC,
        .username = argv[2],
        .user_certificate = (const char *)certificate.data,
        .user_certificate_length = certificate.length,
        .private_key = (const char *)private_key.data,
        .private_key_length = private_key.length,
        .command = argv[6],
        .host_key_algorithms = getenv("TELEPORT_ENGINE_HOST_ALGORITHMS"),
        .sftp_path = getenv("TELEPORT_ENGINE_SFTP_PATH"),
        .input = (const unsigned char *)"teleport-engine-ok",
        .input_length = strlen("teleport-engine-ok"),
        .timeout_milliseconds = 15000,
        .verify_host = compare_host,
        .verify_context = &expected
    };
    result = teleport_ssh_run_command(fd, &request, output, sizeof(output),
                                      &output_length, &exit_status,
                                      &native_error);
    fprintf(stderr, "libssh2=%s result=%d native=%d exit=%d host_bytes=%zu\n",
            libssh2_version(0), result, native_error, exit_status,
            expected.length);
    if(output_length)
        fwrite(output, 1, output_length, stdout);
    memset(private_key.data, 0, private_key.length);
    free(private_key.data); free(certificate.data); free(expected.data);
    return result == TELEPORT_SSH_OK && exit_status != 0 ?
        TELEPORT_SSH_COMMAND : result;
}
