/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _ENCLAVE_TLS_VERIFIER_H
#define _ENCLAVE_TLS_VERIFIER_H

#include <stdint.h>
#include <enclave-tls/compilation.h>
#include <enclave-tls/err.h>
#include <enclave-tls/api.h>
#include <enclave-tls/cert.h>

#define ENCLAVE_VERIFIER_TYPE_MAX 32

#define ENCLAVE_VERIFIER_API_VERSION_1	     1
#define ENCLAVE_VERIFIER_API_VERSION_MAX     ENCLAVE_VERIFIER_API_VERSION_1
#define ENCLAVE_VERIFIER_API_VERSION_DEFAULT ENCLAVE_VERIFIER_API_VERSION_1

#define ENCLAVE_VERIFIER_OPTS_FLAGS_SGX_ENCLAVE 1

#define ENCLAVE_VERIFIER_FLAGS_DEFAULT 0

typedef struct enclave_verifier_ctx enclave_verifier_ctx_t;

typedef struct {
	uint8_t api_version;
	unsigned long flags;
	const char name[ENCLAVE_VERIFIER_TYPE_NAME_SIZE];
	/* Different attester instances may generate the same format of verifier,
	 * e.g, sgx_ecdsa and sgx_ecdsa_qve both generate the format "sgx_ecdsa".
	 * By default, the value of type equals to name.
	 */
	char type[ENCLAVE_VERIFIER_TYPE_NAME_SIZE];
	uint8_t priority;

	/* Optional */
	enclave_verifier_err_t (*pre_init)(void);
	enclave_verifier_err_t (*init)(enclave_verifier_ctx_t *ctx, enclave_tls_cert_algo_t algo);
	enclave_verifier_err_t (*verify_evidence)(enclave_verifier_ctx_t *ctx,
						  attestation_evidence_t *evidence, uint8_t *hash,
						  uint32_t hash_len);
	enclave_verifier_err_t (*collect_collateral)(enclave_verifier_ctx_t *ctx);
	enclave_verifier_err_t (*cleanup)(enclave_verifier_ctx_t *ctx);
} enclave_verifier_opts_t;

struct enclave_verifier_ctx {
	enclave_verifier_opts_t *opts;
	void *verifier_private;
	unsigned long long enclave_id;
	enclave_tls_log_level_t log_level;
	void *handle;

	union {
		struct {
			const char name[ENCLAVE_VERIFIER_TYPE_NAME_SIZE];
			uint8_t spid[ENCLAVE_SGX_SPID_LENGTH];
			bool linkable;
		} sgx_epid;

		struct {
			const char name[ENCLAVE_VERIFIER_TYPE_NAME_SIZE];
			uint8_t cert_type;
		} sgx_ecdsa;
	} config;
};

#endif
