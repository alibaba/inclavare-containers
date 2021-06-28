/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

static unsigned int dummy_private;

tls_wrapper_err_t nulltls_init(tls_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("ctx %p\n", ctx);

	ctx->tls_private = &dummy_private;

	return TLS_WRAPPER_ERR_NONE;
}
