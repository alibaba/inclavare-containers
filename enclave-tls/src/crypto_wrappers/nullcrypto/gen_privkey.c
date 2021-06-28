/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/err.h>
#include <enclave-tls/crypto_wrapper.h>

crypto_wrapper_err_t nullcrypto_gen_privkey(crypto_wrapper_ctx_t *ctx, enclave_tls_cert_algo_t algo,
					    uint8_t *privkey_buf, unsigned int *privkey_len)
{
	ETLS_DEBUG("ctx %p, algo %d, privkey_buf %p, privkey_len %p\n", ctx, algo, privkey_buf,
		   privkey_len);

	/* Indicate no private key generated */
	*privkey_len = 0;

	return CRYPTO_WRAPPER_ERR_NONE;
}
