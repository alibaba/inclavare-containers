/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/api.h>
#include <enclave-tls/log.h>
#include <enclave-tls/attester.h>
#include <string.h>
#include <sgx_error.h>
#include <sgx_report.h>
#include "sgx_la.h"

extern sgx_status_t sgx_generate_evidence(uint8_t *hash, sgx_report_t *app_report);

/* The local attestation requires to exchange the target info between ISV
 * enclaves as the prerequisite. This is out of scope in enclave-tls because it
 * requires to establish a out of band channel to do that. Instead, introduce
 * QE as the intermediator. One ISV enclave as attester can request the local
 * reports signed by QE and the opposite end of ISV enclave as verifier can
 * check the validation of local report through calling sgx_qe_get_attester()
 * which verifies the signed local report. Once getting attester successfully,
 * it presents ISV enclave's local report has been fully verified.
 */
enclave_attester_err_t sgx_la_collect_evidence(enclave_attester_ctx_t *ctx,
					       attestation_evidence_t *evidence,
					       enclave_tls_cert_algo_t algo, uint8_t *hash)
{
	ETLS_DEBUG("ctx %p, evidence %p, algo %d, hash %p\n", ctx, evidence, algo, hash);

	sgx_report_t isv_report;
	sgx_status_t generate_evidence_ret;
	generate_evidence_ret = sgx_generate_evidence(hash, &isv_report);
	if (generate_evidence_ret != SGX_SUCCESS) {
		ETLS_ERR("failed to generate evidence %#x\n", generate_evidence_ret);
		return SGX_LA_ATTESTER_ERR_CODE((int)generate_evidence_ret);
	}

	memcpy(evidence->la.report, &isv_report, sizeof(isv_report));
	evidence->la.report_len = sizeof(isv_report);

	strncpy(evidence->type, "sgx_la", sizeof(evidence->type));

	return ENCLAVE_ATTESTER_ERR_NONE;
}
