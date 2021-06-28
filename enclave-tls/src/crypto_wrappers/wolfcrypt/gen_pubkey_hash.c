/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <enclave-tls/log.h>
#include <enclave-tls/err.h>
#include <enclave-tls/crypto_wrapper.h>
#include "wolfcrypt.h"

/* rsa_pub_3072_pcks_der_len - pcks_nr_1_header_len */
static const int rsa_pub_3072_raw_der_len = 398;

static int gen_rsa3072_pubkey(wolfcrypt_ctx_t *wc_ctx, uint8_t *pub_key_buf,
			      unsigned int *pub_key_len)
{
	/* SetRsaPublicKey() only exports n and e without wrapping them in
	   additional ASN.1 (PKCS#1). */
	uint8_t buf[1024];
	int pub_rsa_key_der_len = SetRsaPublicKey(buf, &wc_ctx->key, sizeof(buf), 0);

	if (pub_rsa_key_der_len != rsa_pub_3072_raw_der_len) {
		ETLS_DEBUG("failed to convert RSA-3072 public key to DER format\n");
		return pub_rsa_key_der_len;
	}

	*pub_key_len = (unsigned int)pub_rsa_key_der_len;
	memcpy(pub_key_buf, buf, (size_t)pub_rsa_key_der_len);

	return 0;
}

crypto_wrapper_err_t wolfcrypt_gen_pubkey_hash(crypto_wrapper_ctx_t *ctx,
					       enclave_tls_cert_algo_t algo, uint8_t *hash)
{
	ETLS_DEBUG("ctx %p, algo %d, hash %p\n", ctx, algo, hash);

	if (!ctx || !hash)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	if (algo != ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256) {
		ETLS_DEBUG("unsupported algorithm %d\n", algo);
		return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;
	}

	wolfcrypt_ctx_t *wc_ctx = (wolfcrypt_ctx_t *)ctx->crypto_private;
	unsigned int pubkey_len;
	uint8_t pubkey_buf[1024];
	int err = gen_rsa3072_pubkey(wc_ctx, pubkey_buf, &pubkey_len);
	if (err)
		return WOLFCRYPT_ERR_CODE(err);

	Sha256 sha256;
	wc_InitSha256(&sha256);
	wc_Sha256Update(&sha256, pubkey_buf, pubkey_len);
	wc_Sha256Final(&sha256, hash);

	ETLS_DEBUG("the sha256 of public key %02x%02x%02x%02x%02x%02x%02x%02x...%02x%02x%02x%02x\n",
		   hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[28],
		   hash[29], hash[30], hash[31]);

	return CRYPTO_WRAPPER_ERR_NONE;
}
