/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   srp_NG3072.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __SRP_NG3072_H__
#define __SRP_NG3072_H__

#include "tiny_base.h"
#include "srp/srp_define.h"

TINY_BEGIN_DECLS


#define srp_N_LEN           384
#define srp_G               5

extern const uint32_t srp_N[srp_N_LEN/4];
extern const uint8_t srp_N_G_hash[srp_HASH_LEN];            // k
extern const uint8_t srp_hash_N_xor_hash_g[srp_HASH_LEN];


TINY_END_DECLS

#endif /* __SRP_NG3072_H__ */
