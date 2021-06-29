/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <enclave-tls/log.h>
#include <enclave-tls/attester.h>
#include <enclave-tls/verifier.h>
#include "sgx_error.h"
#include "sgx_la.h"
#include "sgx_quote_3.h"
#include "sgx_dcap_ql_wrapper.h"

enclave_verifier_err_t ocall_la_verify_evidence(enclave_verifier_ctx_t *ctx,
                                             attestation_evidence_t *evidence,
                                             __attribute__((unused)) uint32_t evidence_len,
                                             uint8_t *hash,
                                             uint32_t hash_len)
{
	uint32_t quote_size = 0;
	unsigned char quote[8192];
	sgx_target_info_t qe_target_info;
	quote3_error_t qe3_ret = SGX_QL_SUCCESS;
	
	printf("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);
	
	// First verify hash value
	sgx_report_t *lreport = (sgx_report_t *)evidence->la.report;

	if (memcmp(hash, lreport->body.report_data.d, hash_len) != 0) {
		printf("Unmatched hash value in evidence\n");
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}
	
	qe3_ret = sgx_qe_get_target_info(&qe_target_info);
	if (SGX_QL_SUCCESS != qe3_ret) {
		printf("failed to get QE's target info %04x\n", qe3_ret);
		return SGX_LA_VERIFIER_ERR_CODE((int)qe3_ret);
	}
	
	qe3_ret = sgx_qe_get_quote_size(&quote_size);
	if (SGX_QL_SUCCESS != qe3_ret) {
		printf("failed to get quote size %04x\n", qe3_ret);
		return SGX_LA_VERIFIER_ERR_CODE((int)qe3_ret);
	}
	
	qe3_ret = sgx_qe_get_quote((sgx_report_t *)evidence->la.report, quote_size, quote);
	if (SGX_QL_SUCCESS != qe3_ret) {
		printf("failed to get quote %04x\n", qe3_ret);
		return SGX_LA_VERIFIER_ERR_CODE((int)qe3_ret);
	}
	
	return ENCLAVE_VERIFIER_ERR_NONE;
}
