/*
 * @Author: CALM.WU
 * @Date: 2021-08-24 15:16:05
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-08-24 16:42:15
 */

#ifndef __EXECVE_DATA_H_
#define __EXECVE_DATA_H_

#include <linux/types.h>

struct data_t
{
	pid_t pid;
    pid_t tid;    
	uid_t uid;
    __s32 ret;    
	char comm[ TASK_COMM_LEN ];
	char filename[ 32 ];
};

#endif // __EXECVE_DATA_H_