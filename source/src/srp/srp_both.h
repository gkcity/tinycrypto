/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   srp_both.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __SRP_BOTH_H__
#define __SRP_BOTH_H__

#include <tiny_lor.h>
#include <tiny_base.h>
#include "srp/srp_define.h"
#include "srp_NG3072.h"

TINY_BEGIN_DECLS


TINY_LOR
TinyRet srp_compute_x(const char username[USERNAME_LEN],
                      const char password[PASSWORD_LEN],
                      const uint8_t salt[salt_LEN],
                      uint8_t x[srp_HASH_LEN]);

TINY_LOR
TinyRet srp_compute_M1(const char username[USERNAME_LEN],
                       const uint8_t salt[salt_LEN],
                       const uint8_t A[A_LEN],
                       const uint8_t B[B_LEN],
                       const uint8_t K[K_LEN],
                       uint8_t M1[M1_LEN]);

TINY_LOR
TinyRet srp_compute_M2(const uint8_t A[A_LEN],
                       const uint8_t M1[M1_LEN],
                       const uint8_t K[K_LEN],
                       uint8_t M2[M2_LEN]);


TINY_END_DECLS

#endif /* __SRP_BOTH_H__ */