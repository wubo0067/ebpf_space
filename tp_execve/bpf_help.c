/*
 * @Author: CALM.WU 
 * @Date: 2021-08-31 11:48:54 
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-08-31 11:49:48
 */

#include "bpf_help.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <time.h>

int bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}