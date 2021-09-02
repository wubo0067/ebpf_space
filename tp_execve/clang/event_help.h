/*
 * @Author: CALM.WU 
 * @Date: 2021-09-01 14:31:28 
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-09-01 15:00:59
 */

#ifndef __EVENT_HELP_H__
#define __EVENT_HELP_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif // 

extern struct timespec start_time;

void handle_event( void* ctx, int32_t cpu, void* data, uint32_t size );

void handle_lost_event( void* ctx, int32_t cpu, uint64_t lost_cnt );

#ifdef __cplusplus
}
#endif //

#endif // __EVENT_HELP_H__