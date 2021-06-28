/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/err.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl.h"

#ifdef WOLFSSL_SGX_WRAPPER
extern int verify_certificate(void *ctx, uint8_t *der_cert, uint32_t der_cert_len);
#else
extern int verify_certificate(int preverify, WOLFSSL_X509_STORE_CTX *store);
#endif

tls_wrapper_err_t wolfssl_internal_negotiate(tls_wrapper_ctx_t *ctx, unsigned long conf_flags,
					     int fd, int (*verify)(int, WOLFSSL_X509_STORE_CTX *))
{
	int flags = WOLFSSL_VERIFY_PEER;
	wolfssl_ctx_t *ws_ctx = ctx->tls_private;

	if ((conf_flags & ENCLAVE_TLS_CONF_FLAGS_MUTUAL) &&
	    (conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER))
		flags |= WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;

	if (verify)
		wolfSSL_CTX_set_verify(ws_ctx->ws, flags, verify);

	WOLFSSL *ssl = wolfSSL_new(ws_ctx->ws);
	if (!ssl)
		return -TLS_WRAPPER_ERR_NO_MEM;

	wolfSSL_SetCertCbCtx(ssl, ctx);

	/* Attach wolfSSL to the socket */
	wolfSSL_set_fd(ssl, fd);

	int err;
	if (conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER)
		err = wolfSSL_negotiate(ssl);
	else
		err = wolfSSL_connect(ssl);

	if (err != SSL_SUCCESS) {
		if (conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER)
			ETLS_DEBUG("failed to negotiate %#x %d\n", err, err);
		else
			ETLS_DEBUG("failed to connect %#x\n", err);

		print_wolfssl_err(ssl);

		return WOLFSSL_ERR_CODE(err);
	}

	ws_ctx->ssl = ssl;

	if (conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER)
		ETLS_DEBUG("success to negotiate\n");
	else
		ETLS_DEBUG("success to connect\n");

	return TLS_WRAPPER_ERR_NONE;
}

#ifdef WOLFSSL_SGX_WRAPPER
static int ssl_ctx_set_verify_callback(int mode, WOLFSSL_X509_STORE_CTX *store)
{
	(void)mode;
	return verify_certificate(store->userCtx, store->certs->buffer, store->certs->length); 
}
#endif

tls_wrapper_err_t wolfssl_negotiate(tls_wrapper_ctx_t *ctx, int fd)
{
	ETLS_DEBUG("ctx %p, fd %d\n", ctx, fd);

	if (!ctx)
		return -TLS_WRAPPER_ERR_INVALID;

	int (*verify)(int, WOLFSSL_X509_STORE_CTX *) = NULL;
	unsigned long conf_flags = ctx->conf_flags;

	if (!(conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER) ||
	    (conf_flags & ENCLAVE_TLS_CONF_FLAGS_MUTUAL)) {
#ifdef WOLFSSL_SGX_WRAPPER
		verify = ssl_ctx_set_verify_callback;
#else
		verify = verify_certificate;
#endif
	}

	return wolfssl_internal_negotiate(ctx, conf_flags, fd, verify);
}
