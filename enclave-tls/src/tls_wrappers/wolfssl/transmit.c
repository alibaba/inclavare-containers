/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl.h"

tls_wrapper_err_t wolfssl_transmit(tls_wrapper_ctx_t *ctx, void *buf, size_t *buf_size)
{
	ETLS_DEBUG("ctx %p, buf %p, buf_size %p\n", ctx, buf, buf_size);

	if (!ctx || !buf || !buf_size)
		return -TLS_WRAPPER_ERR_INVALID;

	wolfssl_ctx_t *ws_ctx = (wolfssl_ctx_t *)ctx->tls_private;
	if (ws_ctx == NULL || ws_ctx->ssl == NULL)
		return -TLS_WRAPPER_ERR_TRANSMIT;

	int rc = wolfSSL_write(ws_ctx->ssl, buf, (int)*buf_size);
	if (rc <= 0) {
		ETLS_DEBUG("ERROR: tls_wrapper_wolfssl transmit()\n");
		return -TLS_WRAPPER_ERR_TRANSMIT;
	}
	*buf_size = (size_t)rc;

	return TLS_WRAPPER_ERR_NONE;
}
