/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _ENCLAVE_TLS_CRYPTO_WRAPPER_H
#define _ENCLAVE_TLS_CRYPTO_WRAPPER_H

#include <stdint.h>
#include <stddef.h>
#include <enclave-tls/compilation.h>
#include <enclave-tls/err.h>
#include <enclave-tls/api.h>
#include <enclave-tls/cert.h>

#define CRYPTO_WRAPPER_TYPE_MAX 32

#define CRYPTO_WRAPPER_API_VERSION_1	   1
#define CRYPTO_WRAPPER_API_VERSION_MAX	   CRYPTO_WRAPPER_API_VERSION_1
#define CRYPTO_WRAPPER_API_VERSION_DEFAULT CRYPTO_WRAPPER_API_VERSION_1

#define CRYPTO_WRAPPER_OPTS_FLAGS_SGX_ENCLAVE 1

typedef struct crypto_wrapper_ctx crypto_wrapper_ctx_t;

typedef struct {
	uint8_t api_version;
	unsigned long flags;
	const char name[CRYPTO_TYPE_NAME_SIZE];
	uint8_t priority;

	/* Optional */
	crypto_wrapper_err_t (*pre_init)(void);
	crypto_wrapper_err_t (*init)(crypto_wrapper_ctx_t *ctx);
	crypto_wrapper_err_t (*gen_privkey)(crypto_wrapper_ctx_t *ctx, enclave_tls_cert_algo_t algo,
					    uint8_t *privkey_buf, unsigned int *privkey_len);
	crypto_wrapper_err_t (*gen_pubkey_hash)(crypto_wrapper_ctx_t *ctx,
						enclave_tls_cert_algo_t algo, uint8_t *hash);
	crypto_wrapper_err_t (*gen_cert)(crypto_wrapper_ctx_t *ctx,
					 enclave_tls_cert_info_t *cert_info);
	crypto_wrapper_err_t (*cleanup)(crypto_wrapper_ctx_t *ctx);
} crypto_wrapper_opts_t;

struct crypto_wrapper_ctx {
	crypto_wrapper_opts_t *opts;
	void *crypto_private;
	/* This field is only used by SGX build. However, we don't want to
	 * make this field conditional because crypto_wrapper_ctx is part
	 * of core libenclave_tls.so which should be a single instance and
	 * commonly available rather than multiple instances for different
	 * build, e.g, common platforms, libos, sgx and so on. This explains
	 * why not use sgx_enclave_id_t to define this field.
	 */
	unsigned long long enclave_id;
	unsigned long conf_flags;
	enclave_tls_log_level_t log_level;
	enclave_tls_cert_algo_t cert_algo;
	void *handle;
};

extern crypto_wrapper_err_t crypto_wrapper_register(const crypto_wrapper_opts_t *);

#endif /* _ENCLAVE_CRYPTO_WRAPPER_H */
