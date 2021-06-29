/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <enclave-tls/verifier.h>
#include <enclave-tls/log.h>

extern enclave_verifier_err_t enclave_verifier_register(enclave_verifier_opts_t *);
extern enclave_verifier_err_t nullverifier_pre_init(void);
extern enclave_verifier_err_t nullverifier_init(enclave_verifier_ctx_t *,
						enclave_tls_cert_algo_t algo);
extern enclave_verifier_err_t nullverifier_verify_evidence(enclave_verifier_ctx_t *,
							   attestation_evidence_t *, uint8_t *,
							   uint32_t hash_len);
extern enclave_verifier_err_t nullverifier_cleanup(enclave_verifier_ctx_t *);

static enclave_verifier_opts_t nullverifier_opts = {
	.api_version = ENCLAVE_VERIFIER_API_VERSION_DEFAULT,
	.flags = ENCLAVE_VERIFIER_FLAGS_DEFAULT,
	.name = "nullverifier",
	.priority = 0,
	.pre_init = nullverifier_pre_init,
	.init = nullverifier_init,
	.verify_evidence = nullverifier_verify_evidence,
	.cleanup = nullverifier_cleanup,
};

#ifdef SGX
void libverifier_null_init(void)
#else
void __attribute__((constructor)) libverifier_null_init(void)
#endif
{
	ETLS_DEBUG("called\n");

	enclave_verifier_err_t err = enclave_verifier_register(&nullverifier_opts);
	if (err != ENCLAVE_VERIFIER_ERR_NONE)
		ETLS_ERR("failed to register the enclave verifier 'nullverifier' %#x\n", err);
}
