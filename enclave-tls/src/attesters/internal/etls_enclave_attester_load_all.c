/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdlib.h>
#ifndef SGX
#include <dirent.h>
#endif
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/attester.h"

// clang-format off
#ifdef OCCLUM
#define PATTERN_SUFFIX  ".so"
#endif
// clang-format on
#ifdef SGX
#include <sgx_error.h>
#include "etls_t.h"
#define DT_REG  8
#endif

static int enclave_attester_cmp(const void *a, const void *b)
{
	return (*(const enclave_attester_ctx_t **)b)->opts->priority -
	       (*(const enclave_attester_ctx_t **)a)->opts->priority;
}

enclave_tls_err_t etls_enclave_attester_load_all(void)
{
	ETLS_DEBUG("called\n");

	uint64_t dir = etls_opendir(ENCLAVE_ATTESTERS_DIR);
	if (!dir) {
		ETLS_ERR("failed to open %s\n", ENCLAVE_ATTESTERS_DIR);
		return -ENCLAVE_TLS_ERR_UNKNOWN;
	}

	unsigned int total_loaded = 0;
	etls_dirent *ptr;
	while (etls_readdir(dir, &ptr) != 1) {
		if (!strcmp(ptr->d_name, ".") || !strcmp(ptr->d_name, "..")) {
			continue;
		}

#ifdef OCCLUM
		/* Occlum can't identify the d_type of the file, always return DT_UNKNOWN */
		if (strncmp(ptr->d_name + strlen(ptr->d_name) - strlen(PATTERN_SUFFIX),
			    PATTERN_SUFFIX, strlen(PATTERN_SUFFIX)) == 0) {
#else
		if (ptr->d_type == DT_REG) {
#endif
			if (etls_enclave_attester_load_single(ptr->d_name) == ENCLAVE_TLS_ERR_NONE)
				++total_loaded;
		}
	}

	etls_closedir((uint64_t)dir);

	if (!total_loaded) {
		ETLS_ERR("unavailable enclave attester instance under %s\n", ENCLAVE_ATTESTERS_DIR);
		return -ENCLAVE_TLS_ERR_LOAD_ENCLAVE_ATTESTERS;
	}

	/* Sort all enclave_attester_ctx_t instances in the enclave_attesters_ctx, and the higher priority
	 * instance should be sorted in front of the enclave_attesters_ctx array.
	 */
	qsort(enclave_attesters_ctx, enclave_attester_nums, sizeof(enclave_attester_ctx_t *),
	      enclave_attester_cmp);

	return ENCLAVE_TLS_ERR_NONE;
}
