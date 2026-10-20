// SPDX-License-Identifier: BSD-3-Clause
// Compile against the patched source's private headers, only for this test.
#include "libssh2_priv.h"
#include <assert.h>
#include <stdio.h>

static const LIBSSH2_HOSTKEY_METHOD *find_method(const char *name)
{
    const LIBSSH2_HOSTKEY_METHOD **method = libssh2_hostkey_methods();
    for(; *method; method++) {
        if(strcmp((*method)->name, name) == 0)
            return *method;
    }
    return NULL;
}

int main(int argc, char **argv)
{
    FILE *file;
    long length;
    unsigned char *blob;
    struct string_buf buf;
    unsigned char *algorithm, *ignored;
    size_t algorithm_length, ignored_length, prefix;
    unsigned int fields, i;
    libssh2_uint64_t serial;
    const LIBSSH2_HOSTKEY_METHOD *method;
    LIBSSH2_SESSION *session;
    void *key = NULL;
    char method_name[80];

    assert(argc == 2);
    assert(libssh2_init(0) == 0);
    file = fopen(argv[1], "rb");
    assert(file && fseek(file, 0, SEEK_END) == 0);
    length = ftell(file);
    assert(length > 0 && length < 1024 * 1024);
    rewind(file);
    blob = malloc((size_t)length + 1);
    assert(blob && fread(blob, 1, (size_t)length, file) == (size_t)length);
    fclose(file);
    buf = (struct string_buf) { blob, blob, (size_t)length };
    assert(_libssh2_get_string(&buf, &algorithm, &algorithm_length) == 0);
    assert(algorithm_length < sizeof(method_name));
    memcpy(method_name, algorithm, algorithm_length);
    method_name[algorithm_length] = 0;
    // RSA certificates use the base key type inside the certificate.
    if(strcmp(method_name, "ssh-rsa-cert-v01@openssh.com") == 0)
        strcpy(method_name, "rsa-sha2-512-cert-v01@openssh.com");
    method = find_method(method_name);
    assert(method && method->init && method->sig_verify);
    session = libssh2_session_init_ex(NULL, NULL, NULL, NULL);
    assert(session && method->init(session, blob, (size_t)length, &key) == 0);
    method->dtor(session, &key);

    // Every incomplete prefix must fail without an out-of-bounds read.
    for(prefix = 0; prefix < (size_t)length; prefix++) {
        assert(method->init(session, blob, prefix, &key) != 0);
        assert(key == NULL);
    }
    blob[length] = 0;
    assert(method->init(session, blob, (size_t)length + 1, &key) != 0);
    assert(key == NULL);

    assert(_libssh2_get_string(&buf, &ignored, &ignored_length) == 0);
    fields = strstr(method_name, "ed25519") ? 1 : 2;
    for(i = 0; i < fields; i++)
        assert(_libssh2_get_string(&buf, &ignored, &ignored_length) == 0);
    assert(_libssh2_get_u64(&buf, &serial) == 0);
    // A user certificate cannot act as a host certificate.
    _libssh2_htonu32(buf.dataptr, 1);
    assert(method->init(session, blob, (size_t)length, &key) != 0);
    assert(key == NULL);
    libssh2_session_free(session);
    free(blob);
    printf("host_import=%s truncated_prefixes=%ld passed\n", method_name, length);
    return 0;
}
