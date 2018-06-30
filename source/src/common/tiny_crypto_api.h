/**
 * Copyright (C) 2013-2015
 *
 * @author jxfengzi@gmail.com
 * @date   2013-7-9
 *
 * @file   tiny_crypto_api.h
 *
 * @remark
 *      set tabstop=4
 *      set shiftwidth=4
 *      set expandtab
 */

#ifndef __TINY_CRYPTO_API_H__
#define __TINY_CRYPTO_API_H__


#ifdef _MSC_VER
#   if  (defined tiny_crypto_shared_EXPORTS)
#       define TINY_CRYPTO_EXPORT _declspec(dllexport)
#   else
#       define TINY_CRYPTO_EXPORT _declspec(dllimport)
#   endif
#   define TINY_CRYPTO_LOCAL
#else
#   ifdef __ANDROID__
#       define TINY_CRYPTO_EXPORT
#       define TINY_CRYPTO_LOCAL
#   else
#       define TINY_CRYPTO_EXPORT __attribute__ ((visibility("default")))
#       define TINY_CRYPTO_LOCAL __attribute__ ((visibility("hidden")))
#   endif /* __ANDROID__ */
#endif /* _MHAP_VER */


#ifdef TINY_CRYPTO_STATIC
#   define TINY_CRYPTO_API
#else
#   define TINY_CRYPTO_API TINY_CRYPTO_EXPORT
#endif /* TINY_CRYPTO_STATIC */


#endif /* __TINY_CRYPTO_API_H__ */
