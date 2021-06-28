/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include "wolfcrypt.h"

crypto_wrapper_err_t wolfcrypt_init(crypto_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("ctx %p\n", ctx);

	if (!ctx)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	wolfcrypt_ctx_t *wc_ctx = calloc(1, sizeof(*wc_ctx));
	if (!wc_ctx)
		return -CRYPTO_WRAPPER_ERR_NO_MEM;

	ctx->crypto_private = wc_ctx;

	return CRYPTO_WRAPPER_ERR_NONE;
}
