/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <enclave-tls/attester.h>
#include <enclave-tls/log.h>

extern enclave_attester_err_t enclave_attester_register(enclave_attester_opts_t *);
extern enclave_attester_err_t sgx_la_attester_pre_init(void);
extern enclave_attester_err_t sgx_la_attester_init(enclave_attester_ctx_t *,
						   enclave_tls_cert_algo_t algo);
extern enclave_attester_err_t sgx_la_collect_evidence(enclave_attester_ctx_t *,
						      attestation_evidence_t *,
						      enclave_tls_cert_algo_t algo, uint8_t *);
extern enclave_attester_err_t sgx_la_attester_cleanup(enclave_attester_ctx_t *);

static enclave_attester_opts_t sgx_la_attester_opts = {
	.api_version = ENCLAVE_ATTESTER_API_VERSION_DEFAULT,
	.flags = ENCLAVE_ATTESTER_OPTS_FLAGS_SGX_ENCLAVE,
	.name = "sgx_la",
	.priority = 15,
	.pre_init = sgx_la_attester_pre_init,
	.init = sgx_la_attester_init,
	.collect_evidence = sgx_la_collect_evidence,
	.cleanup = sgx_la_attester_cleanup,
};

void __attribute__((constructor)) libattester_sgx_la_init(void)
{
	ETLS_DEBUG("called\n");

	enclave_attester_err_t err = enclave_attester_register(&sgx_la_attester_opts);
	if (err != ENCLAVE_ATTESTER_ERR_NONE)
		ETLS_DEBUG("failed to register the enclave attester 'sgx_la' %#x\n", err);
}
