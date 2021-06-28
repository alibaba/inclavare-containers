/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/attester.h>

static unsigned int dummy_private;

enclave_attester_err_t nullattester_init(enclave_attester_ctx_t *ctx, enclave_tls_cert_algo_t algo)
{
	ETLS_DEBUG("ctx %p, algo %d\n", ctx, algo);

	ctx->attester_private = &dummy_private;

	return ENCLAVE_ATTESTER_ERR_NONE;
}
