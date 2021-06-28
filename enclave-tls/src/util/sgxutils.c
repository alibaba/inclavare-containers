/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include "internal/sgxutils.h"

static inline void cpuid(int *eax, int *ebx, int *ecx, int *edx)
{
#if defined(__x86_64__)
	asm volatile("cpuid"
		     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
		     : "0"(*eax), "2"(*ecx)
		     : "memory");
#else
	/* on 32bit, ebx can NOT be used as PIC code */
	asm volatile("xchgl %%ebx, %1; cpuid; xchgl %%ebx, %1"
		     : "=a"(*eax), "=r"(*ebx), "=c"(*ecx), "=d"(*edx)
		     : "0"(*eax), "2"(*ecx)
		     : "memory");
#endif
}

static inline void __cpuidex(int a[4], int b, int c)
{
	a[0] = b;
	a[2] = c;
	cpuid(&a[0], &a[1], &a[2], &a[3]);
}

static bool is_sgx1_supported(void)
{
	int cpu_info[4] = { 0, 0, 0, 0 };

	__cpuidex(cpu_info, SGX_CPUID, 0);

	return !!(cpu_info[0] & 1);
}

static bool is_sgx2_supported(void)
{
	int cpu_info[4] = { 0, 0, 0, 0 };

	__cpuidex(cpu_info, SGX_CPUID, 0);

	return !!(cpu_info[0] & 0x2);
}

static bool is_sgx_device(const char *dev)
{
	struct stat st;

	if (!stat(dev, &st)) {
		if ((st.st_mode & S_IFCHR) && (major(st.st_rdev) == 10))
			return true;
	}

	return false;
}

static bool is_legacy_oot_kernel_driver(void)
{
	return is_sgx_device("/dev/isgx");
}

static bool is_dcap_oot_kernel_driver(void)
{
	return is_sgx_device("/dev/sgx/enclave");
}

static bool is_in_tree_kernel_driver(void)
{
	return is_sgx_device("/dev/sgx_enclave");
}

bool is_sgx_supported_and_configured(void)
{
	if (!is_sgx2_supported() && !is_sgx1_supported())
		return false;

	if (!is_dcap_oot_kernel_driver() && !is_legacy_oot_kernel_driver() &&
	    !is_in_tree_kernel_driver())
		return false;

	return true;
}
