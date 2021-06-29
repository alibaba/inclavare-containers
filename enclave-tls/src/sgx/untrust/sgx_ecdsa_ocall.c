/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>
#include <enclave-tls/log.h>
#include <enclave-tls/attester.h>
#include <enclave-tls/verifier.h>
#include <sgx_urts.h>
#include <sgx_quote.h>
#include <sgx_quote_3.h>
#include <sgx_ql_quote.h>
#include <sgx_dcap_quoteverify.h>
#include <sgx_dcap_ql_wrapper.h>
#include "sgx_ecdsa.h"
#include "etls_u.h"

void get_random_nonce(uint8_t *nonce, uint32_t size)
{
	for (uint32_t i = 0; i < size; i++)
		nonce[i] = (uint8_t)((rand() % 255) + 1);
}

void ocall_ratls_get_target_info(sgx_target_info_t *qe_target_info)
{
	int qe3_ret = sgx_qe_get_target_info(qe_target_info);
	if (SGX_QL_SUCCESS != qe3_ret)
		printf("sgx_qe_get_target_info() with error code 0x%04x\n", qe3_ret);
}

enclave_attester_err_t ocall_qe_get_quote_size(uint32_t *quote_size)
{
	quote3_error_t qe3_ret = sgx_qe_get_quote_size(quote_size);
	if (SGX_QL_SUCCESS != qe3_ret) {
		printf("sgx_qe_get_quote_size(): 0x%04x\n", qe3_ret);
		return SGX_ECDSA_ATTESTER_ERR_CODE((int)qe3_ret);
	}

	return ENCLAVE_ATTESTER_ERR_NONE;
}

enclave_attester_err_t ocall_qe_get_quote(sgx_report_t *report,
                                  uint32_t quote_size,
                                  uint8_t *quote)
{
	quote3_error_t qe3_ret = sgx_qe_get_quote(report,
                                                  quote_size,
                                                  quote);
	if (SGX_QL_SUCCESS != qe3_ret) {
		printf("sgx_qe_get_quote(): 0x%04x\n", qe3_ret);
		return SGX_ECDSA_ATTESTER_ERR_CODE((int)qe3_ret);
	}

	return ENCLAVE_ATTESTER_ERR_NONE;
}

enclave_verifier_err_t ocall_ecdsa_verify_evidence(__attribute__((unused)) enclave_verifier_ctx_t *ctx,
                                                sgx_enclave_id_t enclave_id,
                                                const char *name,
                                                attestation_evidence_t *evidence,
                                                __attribute__((unused)) uint32_t evidence_len,
                                                uint8_t *hash,
                                                uint32_t hash_len)
{
	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;
	uint32_t supplemental_data_size = 0;
	uint8_t *p_supplemental_data = NULL;
	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	uint32_t collateral_expiration_status = 1;
	time_t current_time = 0;
	sgx_isv_svn_t qve_isvsvn_threshold = 3;
	sgx_status_t sgx_ret = SGX_SUCCESS;
	quote3_error_t verify_qveid_ret = SGX_QL_ERROR_UNEXPECTED;
	quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
	sgx_ql_qe_report_info_t *qve_report_info = NULL;
	uint8_t rand_nonce[16];

	sgx_quote3_t *pquote = (sgx_quote3_t *)malloc(8192);
	if (!pquote) {
		printf("failed to malloc sgx quote3 data space.\n");
		return -ENCLAVE_VERIFIER_ERR_NO_MEM;
	}

	memcpy(pquote, evidence->ecdsa.quote, evidence->ecdsa.quote_len);

	uint32_t quote_size = (uint32_t)sizeof(sgx_quote3_t) + pquote->signature_data_len;
	printf("quote size is %d, quote signature_data_len is %d\n", quote_size,
		   pquote->signature_data_len);

	/* First verify the hash value */
	if (memcmp(hash, pquote->report_body.report_data.d, hash_len) != 0) {
		printf("unmatched hash value in evidence.\n");
		err = -ENCLAVE_VERIFIER_ERR_INVALID;
		goto errout;
	}

	/* sgx_ecdsa_qve instance re-uses this code and thus we need to distinguish
	 * it from sgx_ecdsa instance.
	 */
	if (!strcmp(name, "sgx_ecdsa_qve")) {
		qve_report_info = malloc(sizeof(sgx_ql_qe_report_info_t));
		if (!qve_report_info) {
			printf("failed to malloc qve report info.\n");
			goto errout;
		}
		get_random_nonce(rand_nonce, sizeof(rand_nonce));
		memcpy(qve_report_info->nonce.rand, rand_nonce, sizeof(rand_nonce));

		sgx_status_t get_target_info_ret;
		sgx_ret = ecall_get_target_info(enclave_id,
						&get_target_info_ret,
						&qve_report_info->app_enclave_target_info);
		if (sgx_ret != SGX_SUCCESS || get_target_info_ret != SGX_SUCCESS) {
			printf("failed to get target info sgx_ret and get_target_info_ret. %04x, %04x\n",
				sgx_ret, get_target_info_ret);
			err = SGX_ECDSA_VERIFIER_ERR_CODE((int)get_target_info_ret);
			goto errout;
		} else
			printf("get target info successfully.\n");

		dcap_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
		if (dcap_ret == SGX_QL_SUCCESS)
			printf("sgx qv setting for enclave load policy succeeds.\n");
		else {
			printf("failed to set enclave load policy by sgx qv: %04x\n", dcap_ret);
			err = SGX_ECDSA_VERIFIER_ERR_CODE((int)dcap_ret);
			goto errout;
		}
	}

	dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
	if (dcap_ret == SGX_QL_SUCCESS) {
		printf("sgx qv gets quote supplemental data size successfully.\n");
		p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
		if (!p_supplemental_data) {
			printf("failed to malloc supplemental data space.\n");
			err = -ENCLAVE_VERIFIER_ERR_NO_MEM;
			goto errout;
		}
	} else {
		printf("failed to get quote supplemental data size by sgx qv: %04x\n", dcap_ret);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)dcap_ret);
		goto errout;
	}

	current_time = time(NULL);

	dcap_ret = sgx_qv_verify_quote(evidence->ecdsa.quote, (uint32_t)quote_size, NULL,
				       current_time, &collateral_expiration_status,
				       &quote_verification_result, qve_report_info,
				       supplemental_data_size, p_supplemental_data);
	if (dcap_ret == SGX_QL_SUCCESS)
		printf("sgx qv verifies quote successfully.\n");
	else {
		printf("failed to verify quote by sgx qv: %04x\n", dcap_ret);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)dcap_ret);
		goto errret;
	}

	if (!strcmp(name, "sgx_ecdsa_qve")) {
		sgx_ret = sgx_tvl_verify_qve_report_and_identity(
			enclave_id, &verify_qveid_ret, evidence->ecdsa.quote,
			(uint32_t)quote_size, qve_report_info, current_time,
			collateral_expiration_status, quote_verification_result,
			p_supplemental_data, supplemental_data_size, qve_isvsvn_threshold);
		if (sgx_ret != SGX_SUCCESS || verify_qveid_ret != SGX_QL_SUCCESS) {
			printf("verify QvE report and identity failed. %04x\n", verify_qveid_ret);
			err = SGX_ECDSA_VERIFIER_ERR_CODE((int)verify_qveid_ret);
			goto errret;
		} else
			printf("verify QvE report and identity successfully.\n");

		if (qve_report_info) {
			if (memcmp(qve_report_info->nonce.rand, rand_nonce, sizeof(rand_nonce)) !=
			    0) {
				printf("nonce during SGX quote verification has been tampered with.\n");
				err = -ENCLAVE_VERIFIER_ERR_INVALID;
				goto errret;
			}
		}
	}

	/* Check verification result */
	switch (quote_verification_result) {
	case SGX_QL_QV_RESULT_OK:
		printf("verification completed successfully.\n");
		err = ENCLAVE_VERIFIER_ERR_NONE;
		break;
	case SGX_QL_QV_RESULT_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_OUT_OF_DATE:
	case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
	case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
		printf("verification completed with Non-terminal result: %x\n",
			  quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
	case SGX_QL_QV_RESULT_REVOKED:
	case SGX_QL_QV_RESULT_UNSPECIFIED:
	default:
		printf("verification completed with Terminal result: %x\n",
			 quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	}

errret:
	free(p_supplemental_data);
errout:
	free(qve_report_info);
	free(pquote);

	return err;
}
