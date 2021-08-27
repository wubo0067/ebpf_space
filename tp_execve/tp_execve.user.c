/*
 * @Author: CALM.WU
 * @Date: 2021-08-27 11:57:38
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-08-27 15:26:39
 */

#include <stdio.h>
#include <stdlib.h>

#include "tp_execve.skel.h"
#include "event.h"

int32_t main( int32_t argc, char** argv ) { 
    fprintf( stderr, "main: %s\n", argv[0] );
    return 0; 
}