/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/attester.h>
#include <string.h>
#include <sgx_report.h>
#include <sgx_error.h>
//#include "sgx_stub_u.h"
#include "sgx_la.h"

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

	sgx_la_ctx_t *la_ctx = (sgx_la_ctx_t *)ctx->attester_private;

	sgx_report_t isv_report;
	sgx_status_t generate_evidence_ret;
	sgx_status_t status =
		ecall_generate_evidence(la_ctx->eid, &generate_evidence_ret, hash, &isv_report);
	if (status != SGX_SUCCESS || generate_evidence_ret != SGX_SUCCESS) {
		ETLS_ERR("failed to generate evidence %#x\n", generate_evidence_ret);
		return SGX_LA_ATTESTER_ERR_CODE((int)generate_evidence_ret);
	}

	memcpy(evidence->la.report, &isv_report, sizeof(isv_report));
	evidence->la.report_len = sizeof(isv_report);

	strcpy(evidence->type, "sgx_la");

	return ENCLAVE_ATTESTER_ERR_NONE;
}
