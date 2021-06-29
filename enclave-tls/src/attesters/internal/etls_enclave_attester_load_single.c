/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/core.h"
#include "internal/attester.h"

#define PATTERN_PREFIX  "libattester_"
#ifdef SGX
#define PATTERN_SUFFIX  ".a"
#else
#define PATTERN_SUFFIX  ".so"
#endif

enclave_tls_err_t etls_enclave_attester_load_single(const char *fname)
{
	ETLS_DEBUG("loading the enclave attester instance '%s' ...\n", fname);

	/* Check whether the filename pattern matches up libenclave_attester_<name>.so */
	if (strlen(fname) <= strlen(PATTERN_PREFIX) + strlen(PATTERN_SUFFIX) ||
	    strncmp(fname, PATTERN_PREFIX, strlen(PATTERN_PREFIX)) ||
	    strncmp(fname + strlen(fname) - strlen(PATTERN_SUFFIX), PATTERN_SUFFIX,
		    strlen(PATTERN_SUFFIX))) {
		ETLS_ERR("The filename pattern of '%s' NOT match " PATTERN_PREFIX
			 "<name>" PATTERN_SUFFIX "\n",
			 fname);
		return -ENCLAVE_TLS_ERR_INVALID;
	}

	char realpath[strlen(ENCLAVE_ATTESTERS_DIR) + strlen(fname) + 1];
        snprintf(realpath, sizeof(realpath), "%s%s", ENCLAVE_ATTESTERS_DIR, fname);

        size_t name_len = strlen(fname) - strlen(PATTERN_PREFIX) - strlen(PATTERN_SUFFIX);
        char name[name_len + 1];
        strncpy(name, fname + strlen(PATTERN_PREFIX), name_len);
        name[name_len] = '\0';

        void *handle = NULL;
        enclave_tls_err_t err = etls_instance_init(name, realpath, &handle);
        if (err != ENCLAVE_TLS_ERR_NONE)
                return err;

        unsigned int i = 0;
        enclave_attester_opts_t *opts = NULL;
        for (; i < registerd_enclave_attester_nums; ++i) {
                opts = enclave_attesters_opts[i];

		if (!strcmp(name, opts->name))
			break;
	}

	if (i == registerd_enclave_attester_nums) {
		ETLS_DEBUG("the enclave attester '%s' failed to register\n", name);
		return -ENCLAVE_TLS_ERR_NOT_REGISTERED;
	}

	if (opts->pre_init) {
		enclave_attester_err_t err_ea = opts->pre_init();

		if (err_ea != ENCLAVE_ATTESTER_ERR_NONE) {
			ETLS_ERR("failed on pre_init() of enclave attester '%s' %#x\n", name, err_ea);
			return -ENCLAVE_TLS_ERR_INVALID;
		}
	}

	enclave_attester_ctx_t *attester_ctx = calloc(1, sizeof(*attester_ctx));
	if (!attester_ctx)
		return -ENCLAVE_TLS_ERR_NO_MEM;

	attester_ctx->opts = opts;
	attester_ctx->log_level = global_core_context.config.log_level;
	attester_ctx->handle = handle;

	enclave_attesters_ctx[enclave_attester_nums++] = attester_ctx;

	ETLS_DEBUG("the enclave attester '%s' loaded\n", name);

	return ENCLAVE_TLS_ERR_NONE;
}
