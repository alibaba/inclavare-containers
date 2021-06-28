/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <assert.h>
#include <enclave-tls/api.h>
#include "sgx_edger8r.h"
#include "sgx_report.h"
#include "sgx_stub_t.h"
#include "sgx_trts.h"
#include "sgx_utils.h"

sgx_status_t ecall_generate_evidence(uint8_t *hash, sgx_report_t *app_report)
{
	sgx_report_data_t report_data;
	assert(sizeof(report_data.d) >= SHA256_HASH_SIZE);
	memset(&report_data, 0, sizeof(sgx_report_data_t));
	memcpy(report_data.d, hash, SHA256_HASH_SIZE);

	sgx_target_info_t qe_target_info;
	memset(&qe_target_info, 0, sizeof(sgx_target_info_t));
	ocall_ratls_get_target_info(&qe_target_info);

	/* Generate the report for the app_enclave */
	sgx_status_t sgx_error = sgx_create_report(&qe_target_info, &report_data, app_report);
	return sgx_error;
}
