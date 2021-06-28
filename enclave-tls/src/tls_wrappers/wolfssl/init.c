/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl.h"

tls_wrapper_err_t wolfssl_init(tls_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("ctx %p\n", ctx);

	if (!ctx)
		return -TLS_WRAPPER_ERR_INVALID;

	wolfSSL_Init();

	if (ctx->log_level <= ENCLAVE_TLS_LOG_LEVEL_DEBUG)
		wolfSSL_Debugging_ON();
	else
		wolfSSL_Debugging_OFF();

	wolfssl_ctx_t *ws_ctx = calloc(1, sizeof(*ws_ctx));
	if (!ws_ctx)
		return -TLS_WRAPPER_ERR_NO_MEM;

	if (ctx->conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER)
		ws_ctx->ws = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
	else
		ws_ctx->ws = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
	if (!ws_ctx->ws) {
		free(ws_ctx);
		wolfSSL_Cleanup();
		return -TLS_WRAPPER_ERR_NO_MEM;
	}

	ctx->tls_private = ws_ctx;

	return TLS_WRAPPER_ERR_NONE;
}
