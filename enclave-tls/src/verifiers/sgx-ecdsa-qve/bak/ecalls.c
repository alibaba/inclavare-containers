/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sgx_report.h"
#include "sgx_stub_t.h"
#include "sgx_trts.h"
#include "sgx_utils.h"

void sgx_ecdsa_qve_verifier_dummy()
{
}

sgx_status_t ecall_get_target_info(sgx_target_info_t *target_info)
{
	return sgx_self_target(target_info);
}
