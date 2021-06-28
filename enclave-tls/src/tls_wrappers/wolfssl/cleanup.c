/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl.h"

tls_wrapper_err_t wolfssl_cleanup(tls_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("ctx %p\n", ctx);

	if (!ctx)
		return -TLS_WRAPPER_ERR_INVALID;

	wolfssl_ctx_t *ws_ctx = (wolfssl_ctx_t *)ctx->tls_private;

	if (ws_ctx != NULL) {
		if (ws_ctx->ssl != NULL)
			wolfSSL_free(ws_ctx->ssl);
		if (ws_ctx->ws != NULL)
			wolfSSL_CTX_free(ws_ctx->ws);
	}
	free(ws_ctx);

	return TLS_WRAPPER_ERR_NONE;
}
