/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <enclave-tls/api.h>
#include <enclave-tls/log.h>

#include "internal/core.h"
#include "internal/attester.h"
#include "internal/verifier.h"
#include "internal/tls_wrapper.h"

enclave_tls_err_t enclave_tls_cleanup(enclave_tls_handle handle)
{
	etls_core_context_t *ctx = (etls_core_context_t *)handle;

	ETLS_DEBUG("handle %p\n", ctx);

	if (!handle || !handle->tls_wrapper || !handle->tls_wrapper->opts ||
	    !handle->tls_wrapper->opts->cleanup || !handle->attester || !handle->attester->opts ||
	    !handle->attester->opts->cleanup || !handle->verifier || !handle->verifier->opts ||
	    !handle->verifier->opts->cleanup)
		return -ENCLAVE_TLS_ERR_INVALID;

	tls_wrapper_err_t err_tw = handle->tls_wrapper->opts->cleanup(handle->tls_wrapper);
	if (err_tw != TLS_WRAPPER_ERR_NONE) {
		ETLS_DEBUG("failed to clean up tls wrapper %#x\n", err_tw);
		return ENCLAVE_TLS_ERR_INVALID;
	}

	enclave_attester_err_t err_ea = handle->attester->opts->cleanup(handle->attester);
	if (err_ea != ENCLAVE_ATTESTER_ERR_NONE) {
		ETLS_DEBUG("failed to clean up attester %#x\n", err_ea);
		return ENCLAVE_TLS_ERR_INVALID;
	}

	if ((void *)handle->attester != (void *)handle->verifier) {
		enclave_verifier_err_t err_ev = handle->verifier->opts->cleanup(handle->verifier);
		if (err_ev != ENCLAVE_VERIFIER_ERR_NONE) {
			ETLS_DEBUG("failed to clean up verifier %#x\n", err_ev);
			return ENCLAVE_TLS_ERR_INVALID;
		}
	}

	free(ctx);

	return ENCLAVE_TLS_ERR_NONE;
}
