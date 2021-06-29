/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <enclave-tls/log.h>
#include <enclave-tls/verifier.h>
#include <sgx_urts.h>
#include <sgx_quote.h>
#include <sgx_quote_3.h>
#include <sgx_ql_quote.h>
#ifndef SGX
#include <sgx_dcap_quoteverify.h>
#endif
#include "sgx_ecdsa.h"
#ifdef SGX
#include <etls_t.h>
#endif
// clang-format off
#ifdef OCCLUM
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <sys/ioctl.h>
  #include <errno.h>
  #include "quote_verification.h"
#endif
// clang-format on

enclave_verifier_err_t sgx_ecdsa_verify_evidence(enclave_verifier_ctx_t *ctx,
					      attestation_evidence_t *evidence, uint8_t *hash,
					      __attribute__((unused)) uint32_t hash_len)
{
	ETLS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;
#ifdef OCCLUM
	uint32_t supplemental_data_size = 0;
	uint8_t *p_supplemental_data = NULL;
	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	uint32_t collateral_expiration_status = 1;

	int sgx_fd = open("/dev/sgx", O_RDONLY);
	if (sgx_fd < 0) {
		ETLS_ERR("failed to open /dev/sgx\n");
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}

	if (ioctl(sgx_fd, SGXIOC_GET_DCAP_SUPPLEMENTAL_SIZE, &supplemental_data_size) < 0) {
		ETLS_ERR("failed to ioctl get supplemental data size: %s\n", strerror(errno));
		close(sgx_fd);
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}

	p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
	if (!p_supplemental_data) {
		close(sgx_fd);
		return -ENCLAVE_VERIFIER_ERR_NO_MEM;
	}

	memset(p_supplemental_data, 0, supplemental_data_size);

	sgxioc_ver_dcap_quote_arg_t ver_quote_arg = {
		.quote_buf = evidence->ecdsa.quote,
		.quote_size = evidence->ecdsa.quote_len,
		.collateral_expiration_status = &collateral_expiration_status,
		.quote_verification_result = &quote_verification_result,
		.supplemental_data_size = supplemental_data_size,
		.supplemental_data = p_supplemental_data
	};

	if (ioctl(sgx_fd, SGXIOC_VER_DCAP_QUOTE, &ver_quote_arg) < 0) {
		ETLS_ERR("failed to ioctl verify quote: %s\n", strerror(errno));
		close(sgx_fd);
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}

	close(sgx_fd);

	/* Check verification result */
	switch (quote_verification_result) {
	case SGX_QL_QV_RESULT_OK:
		ETLS_INFO("verification completed successfully.\n");
		err = ENCLAVE_VERIFIER_ERR_NONE;
		break;
	case SGX_QL_QV_RESULT_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_OUT_OF_DATE:
	case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
	case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
		ETLS_WARN("verification completed with Non-terminal result: %x\n",
			  quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
	case SGX_QL_QV_RESULT_REVOKED:
	case SGX_QL_QV_RESULT_UNSPECIFIED:
	default:
		ETLS_ERR("verification completed with Terminal result: %x\n",
			 quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	}
#else
	sgx_ecdsa_ctx_t *ecdsa_ctx = (sgx_ecdsa_ctx_t *)ctx->verifier_private;
	sgx_enclave_id_t eid = (sgx_enclave_id_t)ecdsa_ctx->eid;
	ocall_ecdsa_verify_evidence(&err, ctx, eid, ctx->opts->name,
                                    evidence, sizeof(attestation_evidence_t),
                                    hash, hash_len);
#endif

	return err;
}
