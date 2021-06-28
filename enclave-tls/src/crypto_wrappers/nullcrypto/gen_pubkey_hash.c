/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>

crypto_wrapper_err_t nullcrypto_gen_pubkey_hash(crypto_wrapper_ctx_t *ctx,
						enclave_tls_cert_algo_t algo, uint8_t *hash)
{
	ETLS_DEBUG("ctx %p, algo %d, hash %p\n", ctx, algo, hash);

	return CRYPTO_WRAPPER_ERR_NONE;
}