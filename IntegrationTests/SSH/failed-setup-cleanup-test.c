// SPDX-License-Identifier: BSD-3-Clause
#include "libssh2_priv.h"
#include <assert.h>
#include <stdio.h>

static unsigned int destructor_calls;

static int destroy_imported_host_key(LIBSSH2_SESSION *session, void **abstract)
{
    (void)session;
    free(*abstract);
    *abstract = NULL;
    destructor_calls++;
    return 0;
}

int main(int argc, char **argv)
{
    LIBSSH2_HOSTKEY_METHOD host_method = { 0 };
    LIBSSH2_SESSION *session;
    void *imported_key;
    unsigned int expected;
    assert(argc == 2 && (argv[1][0] == '0' || argv[1][0] == '1'));
    expected = (unsigned int)(argv[1][0] - '0');
    assert(libssh2_init(0) == 0);
    session = libssh2_session_init_ex(NULL, NULL, NULL, NULL);
    assert(session);
    imported_key = malloc(1);
    assert(imported_key);
    host_method.dtor = destroy_imported_host_key;
    session->hostkey = &host_method;
    session->server_hostkey_abstract = imported_key;
    // KEX imported a host key, but failed before NEWKEYS could be installed.
    assert(!(session->state & LIBSSH2_STATE_NEWKEYS));
    assert(libssh2_session_free(session) == 0);
    fprintf(stderr, "failed_setup_expected=%u actual=%u\n", expected, destructor_calls);
    assert(destructor_calls == expected);
    if(!destructor_calls)
        free(imported_key);
    printf("failed_setup_host_destructor_calls=%u\n", destructor_calls);
    return 0;
}
