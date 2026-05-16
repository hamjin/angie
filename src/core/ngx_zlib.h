/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_ZLIB_H_INCLUDED_
#define _NGX_ZLIB_H_INCLUDED_


#if (NGX_ZLIB_NG)

#include <zlib-ng.h>

#define z_stream                zng_stream
#define z_streamp               zng_streamp
#define zlibVersion             zlibng_version

#define deflateInit             zng_deflateInit
#define deflateInit2            zng_deflateInit2
#define deflate                 zng_deflate
#define deflateEnd              zng_deflateEnd
#define deflateBound            zng_deflateBound
#define deflateSetDictionary    zng_deflateSetDictionary

#define inflateInit             zng_inflateInit
#define inflateInit2            zng_inflateInit2
#define inflate                 zng_inflate
#define inflateEnd              zng_inflateEnd
#define inflateReset            zng_inflateReset
#define inflateSetDictionary    zng_inflateSetDictionary

#ifdef WITH_GZFILEOP
#define gzopen                  zng_gzopen
#define gzdopen                 zng_gzdopen
#define gzbuffer                zng_gzbuffer
#define gzsetparams             zng_gzsetparams
#define gzread                  zng_gzread
#define gzwrite                 zng_gzwrite
#define gzclose                 zng_gzclose
#define gzerror                 zng_gzerror
#define gzclearerr              zng_gzclearerr
#endif

#else

#include <zlib.h>

#endif


#endif /* _NGX_ZLIB_H_INCLUDED_ */
