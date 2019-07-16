//
// Created by morrowind xie on 2019/5/24.
//

#ifndef _BASE64_H
#define _BASE64_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

int base64_encode(unsigned char *source, size_t sourcelen, char *target, size_t targetlen);

size_t base64_decode(char *source, unsigned char *target, size_t targetlen);

#ifdef __cplusplus
}
#endif

#endif //_BASE64_H
