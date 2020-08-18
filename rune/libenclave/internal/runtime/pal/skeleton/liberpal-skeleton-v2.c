#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include "liberpal-skeleton.h"

int pal_get_version(void)
{
	return 2;
}

int pal_init(pal_attr_t *attr)
{
	return __pal_init(attr);
}

int pal_create_process(pal_create_process_args *args)
{
	return __pal_create_process(args);
}

int pal_exec(pal_exec_args *attr)
{
	return wait4child(attr);
}

int pal_kill(int pid, int sig)
{
	return __pal_kill(pid, sig);
}

int pal_destroy(void)
{
	return __pal_destory();
}
