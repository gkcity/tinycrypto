/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   SrpClient.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __SRP_CLIENT_H__
#define __SRP_CLIENT_H__

#include "tiny_base.h"

TINY_BEGIN_DECLS


struct _SrpClient;
typedef struct _SrpClient SrpClient;

SrpClient *SrpClient_New(const char *username, const char *password);
void SrpClient_Delete(SrpClient *thiz);

TinyRet SrpClient_set_s(SrpClient *thiz, const uint8_t *s, size_t s_len);
TinyRet SrpClient_generate_A(SrpClient *thiz, uint8_t *A, size_t *A_len);
TinyRet SrpClient_compute_u(SrpClient *thiz, const uint8_t *B, size_t B_len, uint8_t *u, size_t *u_len);
TinyRet SrpClient_compute_S(SrpClient *thiz, uint8_t *S, size_t *S_len);
TinyRet SrpClient_compute_K(SrpClient *thiz, uint8_t *k, size_t *K_len);
TinyRet SrpClient_compute_M1(SrpClient *thiz, uint8_t *M1, size_t *M1_len);
TinyRet SrpClient_compute_M2(SrpClient *thiz, uint8_t *M2, size_t *M2_len);


TINY_END_DECLS

#endif /* __SRP_CLIENT_H__ */
