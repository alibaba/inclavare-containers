/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/attester.h>
#include "sgx_ecdsa.h"

enclave_attester_err_t sgx_ecdsa_attester_init(enclave_attester_ctx_t *ctx,
					       enclave_tls_cert_algo_t algo)
{
	ETLS_DEBUG("ctx %p, algo %d\n", ctx, algo);

	sgx_ecdsa_ctx_t *sgx_ecdsa_ctx = calloc(1, sizeof(*sgx_ecdsa_ctx));
	if (!sgx_ecdsa_ctx)
		return -ENCLAVE_ATTESTER_ERR_NO_MEM;

	sgx_ecdsa_ctx->eid = ctx->enclave_id;
	ctx->attester_private = sgx_ecdsa_ctx;

	return ENCLAVE_ATTESTER_ERR_NONE;
}
