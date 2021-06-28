/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/verifier.h>

static unsigned int dummy_private;

enclave_verifier_err_t nullverifier_init(enclave_verifier_ctx_t *ctx, enclave_tls_cert_algo_t algo)
{
	ETLS_DEBUG("ctx %p, algo %d\n", ctx, algo);

	ctx->verifier_private = &dummy_private;

	return ENCLAVE_VERIFIER_ERR_NONE;
}
