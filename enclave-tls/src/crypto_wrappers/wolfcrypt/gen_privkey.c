/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <enclave-tls/log.h>
#include <enclave-tls/err.h>
#include <enclave-tls/crypto_wrapper.h>
#include "wolfcrypt.h"

crypto_wrapper_err_t wolfcrypt_gen_privkey(crypto_wrapper_ctx_t *ctx, enclave_tls_cert_algo_t algo,
					   uint8_t *privkey_buf, unsigned int *privkey_len)
{
	ETLS_DEBUG("ctx %p, algo %d, privkey_buf %p, privkey_len %p\n", ctx, algo, privkey_buf,
		   privkey_len);

	if (!ctx || !privkey_len)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	unsigned int buf_len = *privkey_len;

	ETLS_DEBUG("%d-byte private key buffer requested ...\n", buf_len);

	uint8_t *buf = privkey_buf;
	if (buf_len && !buf)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	if (algo != ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256) {
		ETLS_DEBUG("unsupported algorithm %d\n", algo);
		return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;
	}

	wolfcrypt_ctx_t *wc_ctx = (wolfcrypt_ctx_t *)ctx->crypto_private;
	wc_InitRsaKey(&wc_ctx->key, 0);

	RNG rng;
	wc_InitRng(&rng);
	int ret = wc_MakeRsaKey(&wc_ctx->key, 3072, 65537, &rng);
	if (ret) {
		ETLS_DEBUG("failed to generate RSA-3072 private key %d\n", ret);
		return WOLFCRYPT_ERR_CODE(ret);
	}

	uint8_t der[4096];
	if (!buf_len) {
		buf = der;
		buf_len = sizeof(der);
	}
	int der_sz = wc_RsaKeyToDer(&wc_ctx->key, buf, buf_len);
	if (der_sz < 0 || (unsigned int)der_sz > buf_len) {
		ETLS_DEBUG("failed to convert RSA-3072 private key to DER format %d\n", der_sz);
		return WOLFCRYPT_ERR_CODE(der_sz);
	}

	*privkey_len = (unsigned int)der_sz;

	ETLS_DEBUG("RSA-3072 private key (%d-byte) in DER format generated\n", der_sz);

	return CRYPTO_WRAPPER_ERR_NONE;
}
