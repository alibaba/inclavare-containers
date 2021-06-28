/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <enclave-tls/attester.h>
#include <enclave-tls/log.h>

extern enclave_attester_err_t enclave_attester_register(enclave_attester_opts_t *);
extern enclave_attester_err_t nullattester_pre_init(void);
extern enclave_attester_err_t nullattester_init(enclave_attester_ctx_t *,
						enclave_tls_cert_algo_t algo);
//extern enclave_attester_err_t nullattester_extend_cert(enclave_attester_ctx_t *ctx,
//					    const enclave_tls_cert_info_t *cert_info);
extern enclave_attester_err_t nullattester_collect_evidence(enclave_attester_ctx_t *,
							    attestation_evidence_t *,
							    enclave_tls_cert_algo_t algo,
							    uint8_t *);
extern enclave_attester_err_t nullattester_cleanup(enclave_attester_ctx_t *);

static enclave_attester_opts_t nullattester_opts = {
	.api_version = ENCLAVE_ATTESTER_API_VERSION_DEFAULT,
	.flags = ENCLAVE_ATTESTER_FLAGS_DEFAULT,
	.name = "nullattester",
	.priority = 0,
	.pre_init = nullattester_pre_init,
	.init = nullattester_init,
	//.extend_cert = nullattester_extend_cert,
	.collect_evidence = nullattester_collect_evidence,
	.cleanup = nullattester_cleanup,
};

void __attribute__((constructor)) libattester_null_init(void)
{
	ETLS_DEBUG("called\n");

	enclave_attester_err_t err = enclave_attester_register(&nullattester_opts);
	if (err != ENCLAVE_ATTESTER_ERR_NONE)
		ETLS_ERR("failed to register the enclave attester 'nullattester' %#x\n", err);
}
