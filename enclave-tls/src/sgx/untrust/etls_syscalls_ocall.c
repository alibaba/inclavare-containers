/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "etls_syscalls.h"

void ocall_exit(void)
{
	exit(EXIT_FAILURE);
}

void ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate
	 * the input string to prevent buffer overflow.
	 */
	printf("%s", str);
}

size_t ocall_recv(int sockfd, void *buf, size_t len, int flags)
{
	return recv(sockfd, buf, len, flags);
}

size_t ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
	return send(sockfd, buf, len, flags);
}

// Copy from openenclave
uint64_t ocall_opendir(const char* name)
{
	return (uint64_t)opendir(name);
}

// Copy from openenclave
int ocall_readdir(uint64_t dirp, struct ocall_dirent* entry)
{
	int ret = -1;
	struct dirent* ent;

	errno = 0;

	if (!dirp)
	{
		errno = EBADF;
		goto done;
	}

	if (!entry)
	{
		errno = EINVAL;
		goto done;
	}

	/* Perform the readdir() operation. */
	{
		errno = 0;

 		if (!(ent = readdir((DIR*)dirp)))
		{
			if (errno)
				goto done;

			ret = 1;
			goto done;
		}
	}

	/* Copy the local entry to the caller's entry structure. */
	{
		size_t len = strlen(ent->d_name);

		entry->d_ino = ent->d_ino;
		entry->d_off = ent->d_off;
		entry->d_type = ent->d_type;
		entry->d_reclen = sizeof(struct dirent);

		if (len >= sizeof(entry->d_name))
		{
			errno = ENAMETOOLONG;
			goto done;
		}

		memcpy(entry->d_name, ent->d_name, len + 1);
	}

	ret = 0;

done:
	return ret;
}

// Copy from openenclave
int ocall_closedir(uint64_t dirp)
{
    errno = 0;

    return closedir((DIR*)dirp);
}

ssize_t ocall_read(int fd, void *buf, size_t count)
{
	return read(fd, buf, count);
}

ssize_t ocall_write(int fd, const void *buf, size_t count)
{
	return write(fd, buf, count);
}

void ocall_getenv(const char *name, char *value, size_t len)
{
	memset(value, 0, len);
	char *env_value = getenv(name);
	if (env_value != NULL)
		strncpy(value, env_value, strlen(env_value));
	else
		strncpy(value, "null", len);
}

static double current_time()
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return (double)(1000000 * tv.tv_sec + tv.tv_usec) / 1000000.0;
}

void ocall_current_time(double *time)
{
	if (!time)
		return;

	*time = current_time();

	return;
}

void ocall_low_res_time(int *time)
{
	if (!time)
		return;

	struct timeval tv;
	*time = tv.tv_sec;
}
