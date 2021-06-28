/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/crypto_wrapper.h>
#include <enclave-tls/log.h>

extern crypto_wrapper_err_t nullcrypto_pre_init(void);
extern crypto_wrapper_err_t nullcrypto_init(crypto_wrapper_ctx_t *);
extern crypto_wrapper_err_t nullcrypto_gen_privkey(crypto_wrapper_ctx_t *ctx,
						   enclave_tls_cert_algo_t algo,
						   uint8_t *privkey_buf, unsigned int *privkey_len);
extern crypto_wrapper_err_t nullcrypto_gen_pubkey_hash(crypto_wrapper_ctx_t *,
						       enclave_tls_cert_algo_t, uint8_t *);
extern crypto_wrapper_err_t nullcrypto_gen_cert(crypto_wrapper_ctx_t *, enclave_tls_cert_info_t *);
extern crypto_wrapper_err_t nullcrypto_cleanup(crypto_wrapper_ctx_t *);

static crypto_wrapper_opts_t nullcrypto_opts = {
	.api_version = CRYPTO_WRAPPER_API_VERSION_DEFAULT,
	.name = "nullcrypto",
	.priority = 0,
	.pre_init = nullcrypto_pre_init,
	.init = nullcrypto_init,
	.gen_privkey = nullcrypto_gen_privkey,
	.gen_pubkey_hash = nullcrypto_gen_pubkey_hash,
	.gen_cert = nullcrypto_gen_cert,
	.cleanup = nullcrypto_cleanup,
};

#ifdef SGX
void libcrypto_wrapper_nullcrypto_init(void)
#else
void __attribute__((constructor)) libcrypto_wrapper_nullcrypto_init(void)
#endif
{
	ETLS_DEBUG("called\n");

	crypto_wrapper_err_t err = crypto_wrapper_register(&nullcrypto_opts);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		ETLS_ERR("failed to register the crypto wrapper 'nullcrypto' %#x\n", err);
}
