/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl.h"

tls_wrapper_err_t wolfssl_use_privkey(tls_wrapper_ctx_t *ctx, void *privkey_buf, size_t privkey_len)
{
	ETLS_DEBUG("ctx %p, privkey_buf %p, privkey_len %zu\n", ctx, privkey_buf, privkey_len);

	if (!ctx || !privkey_buf || !privkey_len)
		return -TLS_WRAPPER_ERR_INVALID;

	wolfssl_ctx_t *ws_ctx = (wolfssl_ctx_t *)ctx->tls_private;

	int ret = wolfSSL_CTX_use_PrivateKey_buffer(ws_ctx->ws, privkey_buf, (long)privkey_len,
						    SSL_FILETYPE_ASN1);
	if (ret != SSL_SUCCESS) {
		ETLS_ERR("failed to use private key %d\n", ret);
		return WOLFSSL_ERR_CODE(ret);
	}

	return TLS_WRAPPER_ERR_NONE;
}
