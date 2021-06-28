/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _ENCLAVE_TLS_TLS_WRAPPER_H
#define _ENCLAVE_TLS_TLS_WRAPPER_H

#include <stdint.h>
#include <stddef.h>
#include <enclave-tls/err.h>
#include <enclave-tls/api.h>
#include <enclave-tls/cert.h>

#define TLS_WRAPPER_TYPE_MAX 32

#define TLS_WRAPPER_API_VERSION_1	1
#define TLS_WRAPPER_API_VERSION_MAX	TLS_WRAPPER_API_VERSION_1
#define TLS_WRAPPER_API_VERSION_DEFAULT TLS_WRAPPER_API_VERSION_1

#define TLS_WRAPPER_OPTS_FLAGS_SGX_ENCLAVE 1

typedef struct tls_wrapper_ctx tls_wrapper_ctx_t;

typedef struct {
	uint8_t api_version;
	unsigned long flags;
	const char name[TLS_TYPE_NAME_SIZE];
	uint8_t priority;

	/* Optional */
	tls_wrapper_err_t (*pre_init)(void);
	tls_wrapper_err_t (*init)(tls_wrapper_ctx_t *ctx);
	tls_wrapper_err_t (*use_privkey)(tls_wrapper_ctx_t *ctx, void *privkey_buf,
					 size_t privkey_len);
	tls_wrapper_err_t (*use_cert)(tls_wrapper_ctx_t *ctx, enclave_tls_cert_info_t *cert_info);
	tls_wrapper_err_t (*negotiate)(tls_wrapper_ctx_t *ctx, int fd);
	tls_wrapper_err_t (*transmit)(tls_wrapper_ctx_t *ctx, void *buf, size_t *buf_size);
	tls_wrapper_err_t (*receive)(tls_wrapper_ctx_t *ctx, void *buf, size_t *buf_size);
	tls_wrapper_err_t (*cleanup)(tls_wrapper_ctx_t *ctx);
} tls_wrapper_opts_t;

struct tls_wrapper_ctx {
	/* associate tls wrapper with the enclave verifier instances */
	struct etls_core_context_t *etls_handle;
	tls_wrapper_opts_t *opts;
	void *tls_private;
	int fd;
	unsigned long long enclave_id;
	unsigned long conf_flags;
	enclave_tls_log_level_t log_level;
	void *handle;
};

extern tls_wrapper_err_t tls_wrapper_register(const tls_wrapper_opts_t *);
extern tls_wrapper_err_t tls_wrapper_verify_certificate_extension(tls_wrapper_ctx_t *tls_ctx,
								  attestation_evidence_t *evidence,
								  uint8_t *hash,
								  uint32_t hash_len);

#endif
