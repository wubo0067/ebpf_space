/*
 * @Author: CALM.WU
 * @Date: 2021-08-31 11:47:46
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-08-31 15:13:45
 */

#ifndef __BPF_HELP_H__
#define __BPF_HELP_H__

#ifdef NSEC_PER_SEC
#	undef NSEC_PER_SEC
#endif
#define NSEC_PER_SEC 1000000000ULL

int bump_memlock_rlimit( void );

#endif // __BPF_HELP_H__