/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/attester.h>
#include "sgx_la.h"

enclave_attester_err_t sgx_la_attester_cleanup(enclave_attester_ctx_t *ctx)
{
	ETLS_DEBUG("called\n");

	sgx_la_ctx_t *la_ctx = (sgx_la_ctx_t *)ctx->attester_private;

	free(la_ctx);

	return ENCLAVE_ATTESTER_ERR_NONE;
}
