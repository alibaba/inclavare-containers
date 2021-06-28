/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include "wolfcrypt.h"

crypto_wrapper_err_t wolfcrypt_cleanup(crypto_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("ctx %p\n", ctx);

	wolfcrypt_ctx_t *wc_ctx = (wolfcrypt_ctx_t *)ctx->crypto_private;

	free(wc_ctx);

	return CRYPTO_WRAPPER_ERR_NONE;
}
