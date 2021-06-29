/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <enclave-tls/verifier.h>
#include <enclave-tls/log.h>

extern enclave_verifier_err_t enclave_verifier_register(enclave_verifier_opts_t *);
extern enclave_verifier_err_t sgx_la_verifier_pre_init(void);
extern enclave_verifier_err_t sgx_la_verifier_init(enclave_verifier_ctx_t *,
						   enclave_tls_cert_algo_t algo);
extern enclave_verifier_err_t sgx_la_verify_evidence(enclave_verifier_ctx_t *,
						     attestation_evidence_t *, uint8_t *,
						     unsigned int hash_len);
extern enclave_verifier_err_t sgx_la_verifier_cleanup(enclave_verifier_ctx_t *);

static enclave_verifier_opts_t sgx_la_verifier_opts = {
	.api_version = ENCLAVE_VERIFIER_API_VERSION_DEFAULT,
	.flags = ENCLAVE_VERIFIER_OPTS_FLAGS_SGX_ENCLAVE,
	.name = "sgx_la",
	.priority = 15,
	.pre_init = sgx_la_verifier_pre_init,
	.init = sgx_la_verifier_init,
	.verify_evidence = sgx_la_verify_evidence,
	.cleanup = sgx_la_verifier_cleanup,
};

#ifdef SGX
void libverifier_sgx_la_init(void)
#else
void __attribute__((constructor)) libverifier_sgx_la_init(void)
#endif
{
	ETLS_DEBUG("called\n");

	enclave_verifier_err_t err = enclave_verifier_register(&sgx_la_verifier_opts);
	if (err != ENCLAVE_VERIFIER_ERR_NONE)
		ETLS_DEBUG("failed to register the enclave verifier 'sgx_la' %#x\n", err);
}
