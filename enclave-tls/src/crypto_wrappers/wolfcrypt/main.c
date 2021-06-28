/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/crypto_wrapper.h>
#include <enclave-tls/log.h>
#include <enclave-tls/cert.h>

#ifdef SGX
#define PRIORITY 50
#else
#define PRIORITY 20
#endif

extern crypto_wrapper_err_t wolfcrypt_pre_init(void);
extern crypto_wrapper_err_t wolfcrypt_init(crypto_wrapper_ctx_t *);
extern crypto_wrapper_err_t wolfcrypt_gen_privkey(crypto_wrapper_ctx_t *ctx,
						  enclave_tls_cert_algo_t algo,
						  uint8_t *privkey_buf,
						  unsigned int *privkey_len);
extern crypto_wrapper_err_t wolfcrypt_gen_pubkey_hash(crypto_wrapper_ctx_t *ctx,
						      enclave_tls_cert_algo_t algo, uint8_t *hash);
extern crypto_wrapper_err_t wolfcrypt_gen_cert(crypto_wrapper_ctx_t *ctx,
					       enclave_tls_cert_info_t *cert_info);
extern crypto_wrapper_err_t wolfcrypt_cleanup(crypto_wrapper_ctx_t *);

static crypto_wrapper_opts_t wolfcrypt_opts = {
	.api_version = CRYPTO_WRAPPER_API_VERSION_DEFAULT,
	.name = "wolfcrypt",
	.priority = PRIORITY,
	.pre_init = wolfcrypt_pre_init,
	.init = wolfcrypt_init,
	.gen_privkey = wolfcrypt_gen_privkey,
	.gen_pubkey_hash = wolfcrypt_gen_pubkey_hash,
	.gen_cert = wolfcrypt_gen_cert,
	.cleanup = wolfcrypt_cleanup,
};

#ifdef SGX
void libcrypto_wrapper_wolfcrypt_init(void)
#else
void __attribute__((constructor)) libcrypto_wrapper_wolfcrypt_init(void)
#endif
{
	ETLS_DEBUG("called\n");

	crypto_wrapper_err_t err = crypto_wrapper_register(&wolfcrypt_opts);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		ETLS_ERR("failed to register the crypto wrapper 'wolfcrypt' %#x\n", err);
}
