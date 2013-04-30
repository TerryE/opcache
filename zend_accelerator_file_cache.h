/*
   +----------------------------------------------------------------------+
   | Zend OPcache                                                         |
   +----------------------------------------------------------------------+
   | Copyright (c) 1998-2013 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Terry Ellison<terry@ellisons.org.uk>                        |
   +----------------------------------------------------------------------+
*/
#ifdef OPCACHE_ENABLE_FILE_CACHE
#ifndef ZEND_ACCELERATOR_FILE_CACHE_H
#define ZEND_ACCELERATOR_FILE_CACHE_H

#include "zend.h"
#include <sys/stat.h>

/* OPcache will execute with a multi-level cache (MLC) in the CLI and GCI SAPI modes when configured
   with --enable-opcache-file-cache. The in-memory cache is essentially unchanged from standard
   OPcache use, but an additional cache tier is implemented using a file-based cache.  This include
   file defines the structures, etc. relating to the file cache.
*/

typedef struct _zend_file_cache_record {
	zend_uint compressed_size;
	zend_uint uncompressed_size;
# if (ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO) && !defined(ZTS)
    zend_uint full_interned_size;
    zend_uint compressed_interned_size;
# endif
    zend_uint script_offset;
    zend_uint reloc_bvec_size;
} zend_file_cache_record;

typedef struct _zend_file_cached_script {
    zend_accel_hash_entry  *incache_script_bucket;
    size_t                  record_offset;
    zend_file_cache_record  record;
} zend_file_cached_script;

typedef struct _zend_accel_file_cache_globals {
    zend_bool                file_cache_dirty;
    zend_file_cached_script *file_cached_scripts;
    zend_uint                file_cached_script_count;
    zend_uint                file_cached_script_alloc;
    zend_uint                ophandler_crc;
    FILE                    *fp;
    struct stat              fp_stat_block;
    size_t                   file_next_pos;
    size_t                   file_zero_pos;
    size_t                   next_file_cache_offset;
    FILE                    *fp_tmp;
    char                    *temp_cache_file;
} zend_accel_file_cache_globals;

# define ZFCSG(element)  (accel_shared_globals->fcg.element)

extern int  zend_accel_open_file_cache(TSRMLS_D);
extern void zend_accel_close_file_cache(TSRMLS_D);
extern void zend_accel_save_module_to_file(zend_accel_hash_entry *bucket TSRMLS_DC);
extern void zend_accel_load_module_from_file(zend_uint ndx, zend_accel_hash_entry *bucket TSRMLS_DC);
extern void zend_accel_file_cache_clear_file_cache(void);

#endif /* ZEND_ACCELERATOR_FILE_CACHE_H */
#endif /* OPCACHE_ENABLE_FILE_CACHE */
