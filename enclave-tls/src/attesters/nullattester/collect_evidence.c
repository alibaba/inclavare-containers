/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/attester.h>

enclave_attester_err_t nullattester_collect_evidence(enclave_attester_ctx_t *ctx,
						     attestation_evidence_t *evidence,
						     enclave_tls_cert_algo_t algo, uint8_t *hash)
{
	ETLS_DEBUG("ctx %p, evidence %p, algo %d, hash %p\n", ctx, evidence, algo, hash);

	return ENCLAVE_ATTESTER_ERR_NONE;
}
