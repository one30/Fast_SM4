#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>

void dump_hex(uint8_t * h, int len);

#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X,Y) ((X) > (Y) ? (X) : (Y))

#endif
