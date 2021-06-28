/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/attester.h>
#include <stddef.h>
#include <sgx_uae_service.h>
#include <sgx_quote_3.h>
#include <sgx_ql_quote.h>
//#include <sgx_dcap_quoteverify.h>
//#include <sgx_dcap_ql_wrapper.h>
#include <sgx_ql_lib_common.h>
#include <assert.h>
#include <sgx_error.h>
#include "sgx_ecdsa.h"
//#include "sgx_stub_u.h"
// clang-format off
#ifdef OCCLUM
  #include "sgx_edger8r.h"
  #include "sgx_report.h"
  #include "quote_generation.h"

int generate_quote(int sgx_fd, sgxioc_gen_dcap_quote_arg_t *gen_quote_arg)
{
	if (gen_quote_arg == NULL) {
		ETLS_ERR("NULL gen_quote_arg\n");
		return -1;
	}

	if (ioctl(sgx_fd, SGXIOC_GEN_DCAP_QUOTE, gen_quote_arg) < 0) {
		ETLS_ERR("failed to ioctl get quote\n");
		return -1;
	}

	return 0;
}
#endif
// clang-format on

enclave_attester_err_t sgx_ecdsa_collect_evidence(enclave_attester_ctx_t *ctx,
						  attestation_evidence_t *evidence,
						  enclave_tls_cert_algo_t algo, uint8_t *hash)
{
	ETLS_DEBUG("ctx %p, evidence %p, algo %d, hash %p\n", ctx, evidence, algo, hash);

#ifdef OCCLUM
	int sgx_fd;
	if ((sgx_fd = open("/dev/sgx", O_RDONLY)) < 0) {
		ETLS_ERR("failed to open /dev/sgx\n");
		return -ENCLAVE_ATTESTER_ERR_INVALID;
	}

	sgx_report_data_t report_data = {
		0,
	};
	assert(sizeof(report_data.d) > SHA256_HASH_SIZE);
	memcpy(report_data.d, hash, SHA256_HASH_SIZE);

	uint32_t quote_size = 0;
	if (ioctl(sgx_fd, SGXIOC_GET_DCAP_QUOTE_SIZE, &quote_size) < 0) {
		ETLS_ERR("failed to ioctl get quote size\n");
		return -ENCLAVE_ATTESTER_ERR_INVALID;
	}

	sgxioc_gen_dcap_quote_arg_t gen_quote_arg = { .report_data = &report_data,
						      .quote_len = &quote_size,
						      .quote_buf = evidence->ecdsa.quote };

	if (generate_quote(sgx_fd, &gen_quote_arg) != 0) {
		ETLS_ERR("failed to generate quote\n");
		close(sgx_fd);
		return -ENCLAVE_ATTESTER_ERR_INVALID;
	}
#else
	sgx_ecdsa_ctx_t *ecdsa_ctx = (sgx_ecdsa_ctx_t *)ctx->attester_private;

	sgx_report_t app_report;
	sgx_status_t generate_evidence_ret;
	sgx_status_t status =
		ecall_generate_evidence(ecdsa_ctx->eid, &generate_evidence_ret, hash, &app_report);
	if (status != SGX_SUCCESS || generate_evidence_ret != SGX_SUCCESS) {
		ETLS_ERR("failed to generate evidence %#x, %#x\n", status, generate_evidence_ret);
		return SGX_ECDSA_ATTESTER_ERR_CODE((int)generate_evidence_ret);
	}

	uint32_t quote_size = 0;
	quote3_error_t qe3_ret = sgx_qe_get_quote_size(&quote_size);
	if (SGX_QL_SUCCESS != qe3_ret) {
		ETLS_ERR("sgx_qe_get_quote_size(): 0x%04x\n", qe3_ret);
		return SGX_ECDSA_ATTESTER_ERR_CODE((int)qe3_ret);
	}

	qe3_ret = sgx_qe_get_quote(&app_report, quote_size, evidence->ecdsa.quote);
	if (SGX_QL_SUCCESS != qe3_ret) {
		ETLS_ERR("sgx_qe_get_quote(): 0x%04x\n", qe3_ret);
		return SGX_ECDSA_ATTESTER_ERR_CODE((int)qe3_ret);
	}
#endif

	ETLS_DEBUG("Succeed to generate the quote!\n");

	/* Essentially speaking, sgx_ecdsa_qve verifier generates the same
	 * format of quote as sgx_ecdsa.
	 */
	strcpy(evidence->type, "sgx_ecdsa");
	evidence->ecdsa.quote_len = quote_size;

	return ENCLAVE_ATTESTER_ERR_NONE;
}
