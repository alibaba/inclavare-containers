/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/verifier.h>

enclave_verifier_err_t nullverifier_cleanup(enclave_verifier_ctx_t *ctx)
{
	ETLS_DEBUG("called enclave verifier ctx: %#x\n", ctx);

	return ENCLAVE_VERIFIER_ERR_NONE;
}
