/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _ENCLAVE_TLS_ATTESTER_H
#define _ENCLAVE_TLS_ATTESTER_H

#include <stdint.h>
#include <enclave-tls/compilation.h>
#include <enclave-tls/err.h>
#include <enclave-tls/api.h>
#include <enclave-tls/cert.h>

#define ENCLAVE_ATTESTER_TYPE_MAX 32

#define ENCLAVE_ATTESTER_API_VERSION_1	     1
#define ENCLAVE_ATTESTER_API_VERSION_MAX     ENCLAVE_ATTESTER_API_VERSION_1
#define ENCLAVE_ATTESTER_API_VERSION_DEFAULT ENCLAVE_ATTESTER_API_VERSION_1

#define ENCLAVE_ATTESTER_OPTS_FLAGS_SGX_ENCLAVE 1 << 0

#define ENCLAVE_ATTESTER_FLAGS_DEFAULT 0

typedef struct enclave_attester_ctx enclave_attester_ctx_t;

typedef struct {
	uint8_t api_version;
	unsigned long flags;
	const char name[ENCLAVE_ATTESTER_TYPE_NAME_SIZE];
	/* Different attester instances may generate the same format of attester,
	 * e.g, sgx_ecdsa and sgx_ecdsa_qve both generate the format "sgx_ecdsa".
	 * By default, the value of type equals to name.
	 */
	char type[ENCLAVE_ATTESTER_TYPE_NAME_SIZE];
	uint8_t priority;

	/* Optional */
	enclave_attester_err_t (*pre_init)(void);
	enclave_attester_err_t (*init)(enclave_attester_ctx_t *ctx, enclave_tls_cert_algo_t algo);
	enclave_attester_err_t (*extend_cert)(enclave_attester_ctx_t *ctx,
					      const enclave_tls_cert_info_t *cert_info);
	enclave_attester_err_t (*collect_evidence)(enclave_attester_ctx_t *ctx,
						   attestation_evidence_t *evidence,
						   enclave_tls_cert_algo_t algo, uint8_t *hash);
	enclave_attester_err_t (*cleanup)(enclave_attester_ctx_t *ctx);
} enclave_attester_opts_t;

struct enclave_attester_ctx {
	enclave_attester_opts_t *opts;
	void *attester_private;
	unsigned long long enclave_id;
	enclave_tls_log_level_t log_level;
	void *handle;

	union {
		struct {
			const char name[ENCLAVE_ATTESTER_TYPE_NAME_SIZE];
			uint8_t spid[ENCLAVE_SGX_SPID_LENGTH];
			bool linkable;
		} sgx_epid;

		struct {
			const char name[ENCLAVE_ATTESTER_TYPE_NAME_SIZE];
			uint8_t cert_type;
		} sgx_ecdsa;
	} config;
};

#endif
