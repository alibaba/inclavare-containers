/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/verifier.h>

#include "sgx_la.h"

enclave_verifier_err_t sgx_la_verifier_init(enclave_verifier_ctx_t *ctx,
					    enclave_tls_cert_algo_t algo)
{
	ETLS_DEBUG("ctx %p, algo %d\n", ctx, algo);

	sgx_la_ctx_t *sgx_la_ctx = calloc(1, sizeof(*sgx_la_ctx));
	if (!sgx_la_ctx)
		return -ENCLAVE_VERIFIER_ERR_NO_MEM;

	sgx_la_ctx->eid = ctx->enclave_id;
	ctx->verifier_private = sgx_la_ctx;

	return ENCLAVE_VERIFIER_ERR_NONE;
}
