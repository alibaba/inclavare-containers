/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/verifier.h>
#include "sgx_error.h"
#include "sgx_la.h"
#include "etls_t.h"

/* Refer to explanation in sgx_la_collect_evidence */
enclave_verifier_err_t sgx_la_verify_evidence(enclave_verifier_ctx_t *ctx,
					   attestation_evidence_t *evidence, uint8_t *hash,
					   uint32_t hash_len)
{
	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;

	ocall_la_verify_evidence(&err, ctx,
                                 evidence, sizeof(attestation_evidence_t),
                                 hash, hash_len);

	return err;
}
