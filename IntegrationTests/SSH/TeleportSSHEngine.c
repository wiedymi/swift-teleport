// SPDX-License-Identifier: BSD-3-Clause
#include "TeleportSSHEngine.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <libssh2.h>
#include <libssh2_sftp.h>

static pthread_once_t runtime_once = PTHREAD_ONCE_INIT;
static int runtime_result;

static void start_runtime(void) { runtime_result = libssh2_init(0); }

static uint64_t monotonic_milliseconds(void)
{
    struct timespec time;
    uint64_t seconds, fraction;
    if(clock_gettime(CLOCK_MONOTONIC, &time) != 0)
        return 0;
    if(time.tv_sec < 0 || time.tv_nsec < 0 || time.tv_nsec >= 1000000000)
        return 0;
    seconds = (uint64_t)time.tv_sec;
    fraction = (uint64_t)time.tv_nsec / 1000000;
    if(seconds > (UINT64_MAX - fraction) / 1000)
        return 0;
    return seconds * 1000 + fraction;
}

static int wait_ready(LIBSSH2_SESSION *session, int fd, uint64_t deadline)
{
    for(;;) {
        uint64_t now = monotonic_milliseconds();
        uint64_t remaining;
        int directions, result;
        struct pollfd descriptor;
        if(!now || now >= deadline)
            return -1;
        remaining = deadline - now;
        directions = libssh2_session_block_directions(session);
        descriptor.fd = fd;
        descriptor.events = 0;
        descriptor.revents = 0;
        if(directions & LIBSSH2_SESSION_BLOCK_INBOUND)
            descriptor.events |= POLLIN;
        if(directions & LIBSSH2_SESSION_BLOCK_OUTBOUND)
            descriptor.events |= POLLOUT;
        if(!descriptor.events)
            descriptor.events = POLLIN;
        result = poll(&descriptor, 1,
                      remaining > INT_MAX ? INT_MAX : (int)remaining);
        if(result > 0)
            return (descriptor.revents & POLLNVAL) ? -1 : 0;
        if(result < 0 && errno == EINTR)
            continue;
        return -1;
    }
}

static enum TeleportSSHResult sftp_roundtrip(
    LIBSSH2_SESSION *session, int fd, uint64_t deadline,
    const struct TeleportSSHCommand *request, unsigned char *output,
    size_t capacity, size_t *length, int *native_error)
{
    LIBSSH2_SFTP *sftp = NULL;
    LIBSSH2_SFTP_HANDLE *handle = NULL;
    enum TeleportSSHResult result = TELEPORT_SSH_SFTP;
    int rc = 0, created = 0;
    size_t offset = 0, used = 0;
    unsigned int path_length = (unsigned int)strlen(request->sftp_path);

#define SFTP_WAIT() do { \
    if(wait_ready(session, fd, deadline) != 0) { \
        result = TELEPORT_SSH_TIMEOUT; goto cleanup; \
    } \
} while(0)

    while(!(sftp = libssh2_sftp_init(session))) {
        rc = libssh2_session_last_errno(session);
        if(rc != LIBSSH2_ERROR_EAGAIN)
            goto cleanup;
        SFTP_WAIT();
    }
    while(!(handle = libssh2_sftp_open_ex(sftp, request->sftp_path, path_length,
                LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_EXCL,
                0600, LIBSSH2_SFTP_OPENFILE))) {
        rc = libssh2_session_last_errno(session);
        if(rc != LIBSSH2_ERROR_EAGAIN)
            goto cleanup;
        SFTP_WAIT();
    }
    created = 1;
    while(offset < request->input_length) {
        size_t remaining = request->input_length - offset;
        ssize_t count = libssh2_sftp_write(handle,
            (const char *)request->input + offset, remaining > 8192 ? 8192 : remaining);
        if(monotonic_milliseconds() >= deadline) {
            result = TELEPORT_SSH_TIMEOUT;
            goto cleanup;
        }
        if(count > 0) {
            offset += (size_t)count;
            continue;
        }
        if(count < 0 && count != LIBSSH2_ERROR_EAGAIN) {
            rc = (int)count;
            goto cleanup;
        }
        SFTP_WAIT();
    }
    do {
        rc = libssh2_sftp_close_handle(handle);
        if(rc == LIBSSH2_ERROR_EAGAIN) SFTP_WAIT();
    } while(rc == LIBSSH2_ERROR_EAGAIN);
    handle = NULL;
    if(rc != 0)
        goto cleanup;
    while(!(handle = libssh2_sftp_open_ex(sftp, request->sftp_path, path_length,
                LIBSSH2_FXF_READ, 0, LIBSSH2_SFTP_OPENFILE))) {
        rc = libssh2_session_last_errno(session);
        if(rc != LIBSSH2_ERROR_EAGAIN)
            goto cleanup;
        SFTP_WAIT();
    }
    for(;;) {
        unsigned char buffer[8192];
        ssize_t count = libssh2_sftp_read(handle, (char *)buffer, sizeof(buffer));
        if(monotonic_milliseconds() >= deadline) {
            result = TELEPORT_SSH_TIMEOUT;
            goto cleanup;
        }
        if(count > 0) {
            if((size_t)count > capacity - used) {
                result = TELEPORT_SSH_OUTPUT_LIMIT;
                goto cleanup;
            }
            memcpy(output + used, buffer, (size_t)count);
            used += (size_t)count;
            continue;
        }
        if(count == 0)
            break;
        if(count != LIBSSH2_ERROR_EAGAIN) {
            rc = (int)count;
            goto cleanup;
        }
        SFTP_WAIT();
    }
    if(used != request->input_length || memcmp(output, request->input, used))
        goto cleanup;
    result = TELEPORT_SSH_OK;

cleanup:
    // The test runner uses its own thread. Limit cleanup even after a failed
    // request; production package I/O does not use this blocking adapter.
    libssh2_session_set_blocking(session, 1);
    libssh2_session_set_timeout(session, 1000);
    if(handle && libssh2_sftp_close_handle(handle) != 0 && result == TELEPORT_SSH_OK)
        result = TELEPORT_SSH_SFTP;
    if(created && libssh2_sftp_unlink_ex(sftp, request->sftp_path, path_length) != 0 &&
       result == TELEPORT_SSH_OK)
        result = TELEPORT_SSH_SFTP;
    if(sftp && libssh2_sftp_shutdown(sftp) != 0 && result == TELEPORT_SSH_OK)
        result = TELEPORT_SSH_SFTP;
    *length = used;
    *native_error = rc;
    return result;

#undef SFTP_WAIT
}

enum TeleportSSHResult teleport_ssh_run_command(
    int fd, const struct TeleportSSHCommand *request,
    unsigned char *output, size_t output_capacity, size_t *output_length,
    int *exit_status, int *native_error)
{
    LIBSSH2_SESSION *session = NULL;
    LIBSSH2_CHANNEL *channel = NULL;
    enum TeleportSSHResult result = TELEPORT_SSH_INPUT;
    size_t used = 0;
    uint64_t now, deadline;
    int flags, rc = 0;
    size_t username_length;
    const char *host_certificate;
    size_t host_certificate_length;

    if(output_length) *output_length = 0;
    if(exit_status) *exit_status = -1;
    if(native_error) *native_error = 0;
    if(fd < 0 || !request || !request->username ||
       !request->user_certificate || !request->user_certificate_length ||
       request->user_certificate_length > 350000 ||
       !request->private_key || !request->private_key_length ||
       request->private_key_length > 16384 ||
       !request->verify_host ||
       !request->timeout_milliseconds || !output || !output_capacity ||
       !output_length || !exit_status || !native_error)
        goto cleanup;
    if(request->operation != TELEPORT_SSH_EXEC &&
       request->operation != TELEPORT_SSH_PTY_RESIZE &&
       request->operation != TELEPORT_SSH_SFTP_ROUNDTRIP)
        goto cleanup;
    if(request->operation == TELEPORT_SSH_SFTP_ROUNDTRIP) {
        if(!request->sftp_path || !request->sftp_path[0] ||
           strlen(request->sftp_path) > 4096 || !request->input ||
           !request->input_length || request->input_length > output_capacity)
            goto cleanup;
    } else if(!request->command || strlen(request->command) > 65536) {
        goto cleanup;
    }
    username_length = strlen(request->username);
    if(!username_length || username_length > 255)
        goto cleanup;
    now = monotonic_milliseconds();
    if(!now || now > UINT64_MAX - request->timeout_milliseconds)
        goto cleanup;
    deadline = now + request->timeout_milliseconds;
    pthread_once(&runtime_once, start_runtime);
    result = TELEPORT_SSH_SETUP;
    if(runtime_result != 0)
        goto cleanup;
    flags = fcntl(fd, F_GETFL);
    if(flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        goto cleanup;
#ifdef SO_NOSIGPIPE
    {
        int enabled = 1;
        if(setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE,
                      &enabled, sizeof(enabled)) < 0)
            goto cleanup;
    }
#endif
    session = libssh2_session_init_ex(NULL, NULL, NULL, NULL);
    if(!session)
        goto cleanup;
    libssh2_session_set_blocking(session, 0);
    rc = libssh2_session_method_pref(session, LIBSSH2_METHOD_HOSTKEY,
        request->host_key_algorithms ? request->host_key_algorithms :
        "ssh-ed25519-cert-v01@openssh.com,"
        "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
        "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
        "ecdsa-sha2-nistp521-cert-v01@openssh.com,"
        "rsa-sha2-512-cert-v01@openssh.com,"
        "rsa-sha2-256-cert-v01@openssh.com");
    if(rc != 0)
        goto cleanup;

#define WAIT_OR_TIMEOUT() do { \
    if(wait_ready(session, fd, deadline) != 0) { \
        result = TELEPORT_SSH_TIMEOUT; goto cleanup; \
    } \
} while(0)

    result = TELEPORT_SSH_HANDSHAKE;
    while((rc = libssh2_session_handshake(session, fd)) ==
          LIBSSH2_ERROR_EAGAIN)
        WAIT_OR_TIMEOUT();
    if(rc != 0)
        goto cleanup;
    result = TELEPORT_SSH_HOST_TRUST;
    host_certificate = libssh2_session_hostkey(session,
                                               &host_certificate_length,
                                               NULL);
    if(!host_certificate || !host_certificate_length ||
       request->verify_host((const unsigned char *)host_certificate,
                            host_certificate_length,
                            request->verify_context) != 0)
        goto cleanup;

    result = TELEPORT_SSH_AUTH;
    while((rc = libssh2_userauth_publickey_frommemory(session,
                request->username, username_length,
                request->user_certificate, request->user_certificate_length,
                request->private_key, request->private_key_length, NULL)) ==
          LIBSSH2_ERROR_EAGAIN)
        WAIT_OR_TIMEOUT();
    if(rc != 0)
        goto cleanup;

    if(request->operation == TELEPORT_SSH_SFTP_ROUNDTRIP) {
        result = sftp_roundtrip(session, fd, deadline, request, output,
                               output_capacity, &used, &rc);
        if(result == TELEPORT_SSH_OK)
            *exit_status = 0;
        goto cleanup;
    }

    result = TELEPORT_SSH_CHANNEL;
    while(!(channel = libssh2_channel_open_ex(session, "session", 7,
                LIBSSH2_CHANNEL_WINDOW_DEFAULT, LIBSSH2_CHANNEL_PACKET_DEFAULT,
                NULL, 0))) {
        rc = libssh2_session_last_errno(session);
        if(rc != LIBSSH2_ERROR_EAGAIN)
            goto cleanup;
        WAIT_OR_TIMEOUT();
    }
    rc = libssh2_channel_handle_extended_data2(
        channel, LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE);
    if(rc != 0)
        goto cleanup;
    if(request->operation == TELEPORT_SSH_PTY_RESIZE) {
        while((rc = libssh2_channel_request_pty_ex(channel, "xterm", 5,
                    NULL, 0, 80, 24, 0, 0)) == LIBSSH2_ERROR_EAGAIN)
            WAIT_OR_TIMEOUT();
        if(rc != 0)
            goto cleanup;
    }
    result = TELEPORT_SSH_COMMAND;
    while((rc = libssh2_channel_process_startup(channel, "exec", 4,
                request->command, (unsigned int)strlen(request->command))) ==
          LIBSSH2_ERROR_EAGAIN)
        WAIT_OR_TIMEOUT();
    if(rc != 0)
        goto cleanup;

    if(request->operation == TELEPORT_SSH_PTY_RESIZE) {
        static const char marker[] = "<teleport-pty-ready>";
        char received[sizeof(marker) - 1];
        size_t matched = 0;
        // The remote command installs its WINCH trap before this marker. The
        // resize must reach a running session, rather than only its PTY request.
        while(matched < sizeof(received)) {
            ssize_t count = libssh2_channel_read_ex(channel, 0,
                received + matched, sizeof(received) - matched);
            if(count > 0) {
                if(memcmp(received + matched, marker + matched, (size_t)count)) {
                    rc = LIBSSH2_ERROR_PROTO;
                    goto cleanup;
                }
                matched += (size_t)count;
                continue;
            }
            if(count < 0 && count != LIBSSH2_ERROR_EAGAIN) {
                rc = (int)count;
                goto cleanup;
            }
            if(libssh2_channel_eof(channel)) {
                rc = LIBSSH2_ERROR_PROTO;
                goto cleanup;
            }
            WAIT_OR_TIMEOUT();
        }
        while((rc = libssh2_channel_request_pty_size_ex(channel, 121, 43, 0, 0)) ==
              LIBSSH2_ERROR_EAGAIN)
            WAIT_OR_TIMEOUT();
        if(rc != 0)
            goto cleanup;
    }

    for(;;) {
        unsigned char buffer[8192];
        if(monotonic_milliseconds() >= deadline) {
            result = TELEPORT_SSH_TIMEOUT;
            goto cleanup;
        }
        ssize_t count = libssh2_channel_read_ex(channel, 0,
                                               (char *)buffer, sizeof(buffer));
        if(count > 0) {
            if((size_t)count > output_capacity - used) {
                result = TELEPORT_SSH_OUTPUT_LIMIT;
                goto cleanup;
            }
            memcpy(output + used, buffer, (size_t)count);
            used += (size_t)count;
            continue;
        }
        if(count < 0 && count != LIBSSH2_ERROR_EAGAIN) {
            rc = (int)count;
            goto cleanup;
        }
        if(libssh2_channel_eof(channel))
            break;
        WAIT_OR_TIMEOUT();
    }
    while((rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN)
        WAIT_OR_TIMEOUT();
    if(rc != 0)
        goto cleanup;
    if(!libssh2_channel_has_exit_status(channel))
        goto cleanup;
    *exit_status = libssh2_channel_get_exit_status(channel);
    result = TELEPORT_SSH_OK;

cleanup:
    if(output_length) *output_length = used;
    if(native_error) *native_error = rc;
    // No operation uses fd after this thread finishes the native session.
    // Shutdown first prevents native teardown from waiting for the remote peer.
    if(fd >= 0)
        shutdown(fd, SHUT_RDWR);
    if(session) {
        libssh2_session_set_blocking(session, 1);
        libssh2_session_set_timeout(session, 1000);
    }
    if(channel)
        libssh2_channel_free(channel);
    if(session)
        libssh2_session_free(session);
    if(fd >= 0)
        close(fd);
    return result;

#undef WAIT_OR_TIMEOUT
}
