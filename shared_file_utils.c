/*
   +----------------------------------------------------------------------+
   | Zend Optimizer+                                                      |
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
#include "main/php.h"
#include "main/php_globals.h"
#include "zend.h"
#include "zend_extensions.h"
#include "zend_compile.h"
#include "ZendAccelerator.h"
#ifdef OPCACHE_ENABLE_FILE_CACHE

#include "zend_shared_alloc.h"
#include "zend_accelerator_util_funcs.h"
#include "lz4/lz4.h"
#include "lz4/lz4hc.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/mman.h>
#include <zlib.h>
#include "SAPI.h"

#if ZEND_EXTENSION_API_NO >= PHP_5_3_X_API_NO
# include "ext/ereg/php_regex.h"
#else
# include "main/php_regex.h"
#endif
#include <pcre.h> 

#ifdef ZEND_WIN32
# define REGEX_MODE (REG_EXTENDED|REG_NOSUB|REG_ICASE)
#else
# define REGEX_MODE (REG_EXTENDED|REG_NOSUB)
#endif

#include "zend_API.h"
#include "zend_alloc.h"
#include "zend_hash.h"
#include "zend_variables.h"

#include "ext/standard/info.h"
#include "ext/standard/file.h"

#include <string.h>
#include <errno.h>


/* Notes:

   1) Even thought the will only ever by one thread for CLI and GCI processes, CLI persistance is
      still TSRM enabled to allow CLI based testing of TSRM builds.

   2) TODO: add compile-time checks only to enable OPCACHE_ENABLE_FILE_CACHE when PCRE is available.

   3) TODO: GCC on ZCG(cache_path)

   4) TODO: zend_accel_save_sma() runs as part of image rundown by which time a lot of PHP services 
            have run down.  might be worth bumping its hook back to request shutdown to make life 
            simpler.
*/
#define CHUNK 65536
#define TMP_FILE_PREFIX ".OPcache."
#define CHECK(p) if(!(p)) goto error
#define EFREE(p) if(p) efree(p)

#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
#  define MAX_OPCODE     156       /* 3 new opcodes in 5.4 - separate, bind_trais, add_trait */
#elif ZEND_EXTENSION_API_NO == PHP_5_3_X_API_NO
#  define MAX_OPCODE     153       /* 3 new opcodes in 5.3 - unused, lambda, jmp_set */
# else
#  define MAX_OPCODE     150
# endif
#define OPCODE_TABLE_SIZE 25*MAX_OPCODE+26
#define FINGERPRINT_SIZE sizeof("OPcache==0x12345678==..")
#define FINGERPRINT_FORMAT      "OPcache==0x%08u==\r\n"
#define SCRIPT_VEC_HEADROOM 32

#if SIZEOF_SIZE_T == 8
# define ADDR_HI_SET ((size_t) 0x8000000000000000)
#else
# define ADDR_HI_SET ((size_t) 0x80000000)
#endif

typedef struct _fc_index_header {
    char        fingerprint[FINGERPRINT_SIZE];

	zend_uint   compressed_size;
	zend_uint   uncompressed_size;
    zend_uint   script_count;
    zend_uint   max_include_paths_entry;
    zend_uint   max_hash_entry;
# if (ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO) && !defined(ZTS)
    zend_uint   interned_base_count;
    zend_uint   interned_base_tail;
    zend_uint   interned_strings_count;
#endif    
} fc_index_header;

static char     *generate_cache_name(TSRMLS_D);
static zend_uint make_block_rbvec(void *block, zend_uint block_size, char **rbvec);
static void      relocate_script(zend_file_cached_script *entry, char *memory_area, char *rbvec, char *interned);
static void      resize_file_cached_script_vec(void);
# if (ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO) && !defined(ZTS)
static zend_uint make_interned_vars(zend_file_cached_script *script, char **interned_vec);
#endif
static FILE     *open_temporary_file(char* prefix, char **name TSRMLS_DC);
static int       write_index_to_file(FILE *fd);
static size_t    copy_file(FILE *in, FILE *out);
static int       cache_compress(const char* source, char** dest, int source_size);
static int       cache_decompress(const char* source, char* dest, int source_size, int dest_size);

int zend_accel_open_file_cache(TSRMLS_D)
{ENTER(zend_accel_open_file_cache)
    FILE                   *fp = NULL;
    char                    header_fingerprint[FINGERPRINT_SIZE];
    char                   *cbuf = NULL, *obuf, *p;
    ulong                   obuf_len;
    char                   *errmsg;
    zend_uint               i;
    size_t                  offset;
	fc_index_header         header;
    zend_file_cache_record *r;
    zend_accel_hash_entry  *bucket;

#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO && !defined(ZTS)
    ZFCSG(interned_skip) = ZCSG(interned_strings).nNumOfElements;
    ZFCSG(interned_base) = ZCSG(interned_strings).pListTail;
#endif

    if ((ZCG(cache_path) = generate_cache_name(TSRMLS_C)) == NULL) {
        /* no cache file so fail through to defaul (no file cache) processing */
        zend_accel_error(ACCEL_LOG_INFO, "LOAD: no cache file specified");
        return 0;
    }

    /* The cache contains op_arrays which reference entries from the zend_opcode_handlers vector, so
       it is specific to a given PHP build; so use the CRC of the vector as a build fingerprint */
    ZFCSG(ophandler_crc) = zend_adler32(ADLER32_INIT, (signed char *)zend_opcode_handlers, OPCODE_TABLE_SIZE * sizeof(void *));
    memset(&header, 0, sizeof(header));
    sprintf(header_fingerprint, FINGERPRINT_FORMAT, ZFCSG(ophandler_crc));

    if (ZCG(cache_path)[0] != '/' ||
        (fp = fopen(ZCG(cache_path), "rb")) == NULL) {
        /* cache isn't a valid file or we can't open it so again fail through */ 
        DEBUG1(LOAD,"LOAD: Cache file %s does not exist", ZCG(cache_path));
        return 1;
    }


    if (fread((void *) &header, 1, sizeof(header), fp) != sizeof(header)
        || memcmp(header_fingerprint, header.fingerprint, FINGERPRINT_SIZE) != 0 
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO && !defined(ZTS)
        || ZFCSG(interned_skip) != header.interned_base_count
        || ZFCSG(interned_base) != (Bucket*)(ZCSG(interned_strings_start) + header.interned_base_tail)
#endif
        ) {
    	zend_accel_error(ACCEL_LOG_WARNING, "Fingerprint mismatch on File cache", errmsg);
        ZFCSG(file_cache_dirty) = 1;
        fclose(fp);
	    zend_shared_alloc_unlock(TSRMLS_C);
        return 0;
    }

    DEBUG5(INDEX, "Cache File header - CS:%u US:%u SC:%u #I:%u #H:%u",  header.compressed_size, 
                  header.uncompressed_size, header.script_count, 
                  header.max_include_paths_entry, header.max_hash_entry);
# if (ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO) && !defined(ZTS)
    DEBUG3(INDEX,"Cache File header - #IBC:%u #IC:%u ICO:%u",  header.interned_base_count,
                 header.interned_strings_count, header.interned_base_tail);
#endif    

    errmsg = "unable to stat file";
	CHECK(fstat(fileno(fp), &ZFCSG(fp_stat_block)) == 0);

    cbuf = emalloc(header.compressed_size);
    errmsg = "unable to read index";
    CHECK(fread((void *) cbuf, 1, header.compressed_size, fp) == header.compressed_size);

    /* move and expand index to SMA because its strings are used to generate the SMA hashes */
    obuf_len = header.uncompressed_size;
	zend_shared_alloc_lock(TSRMLS_C);

    obuf = zend_shared_alloc(obuf_len);
    CHECK(cache_decompress(cbuf, obuf, header.compressed_size, header.uncompressed_size));
    efree(cbuf);
    cbuf = NULL;
    
    ZFCSG(file_cached_script_count) = header.script_count;
    ZFCSG(file_cached_script_alloc) = header.script_count + SCRIPT_VEC_HEADROOM;
    ZFCSG(file_cached_scripts) = emalloc(ZFCSG(file_cached_script_alloc)*sizeof(zend_file_cached_script));
    memset(ZFCSG(file_cached_scripts) + header.script_count, 0, SCRIPT_VEC_HEADROOM*sizeof(zend_file_cached_script));

    offset = sizeof(header) + header.compressed_size;

#define CHECK_MARKER() CHECK(!strcmp(p,"****")); p+=5;

    for (i = 0, r = (zend_file_cache_record *) obuf; i < header.script_count; i++, r++) {
        ZFCSG(file_cached_scripts)[i].record = *r;
        ZFCSG(file_cached_scripts)[i].record_offset = offset;
        offset += r->compressed_size +
                  r->reloc_bvec_size;
        ZFCSG(file_cached_scripts)[i].incache_script_bucket = NULL;
    }

    ZFCSG(next_file_cache_offset) = offset;
    p = (char *) r;




    CHECK_MARKER();

    /* scan include_paths string, index computed from num_entries */
    zend_accel_hash_clean(&ZCSG(include_paths));
    for (i = 0;  i < header.max_include_paths_entry; i++) {
        zend_uint include_path_len = strlen(p);
        CHECK(p[include_path_len+2] == 0);
        p[include_path_len+1] = 'A' + ZCSG(include_paths).num_entries;
	    if (!zend_accel_hash_find(&ZCSG(include_paths), p, include_path_len + 1)) {
    		zend_accel_hash_update(&ZCSG(include_paths), p, include_path_len + 1, 0, p + include_path_len + 1);
        }
        DEBUG1(INDEX, "include path:%s", p);
        p += include_path_len + 3;
    }

    CHECK_MARKER();

    /* scan the script_count direct hash entries, data points to the corresponding file_cached_scripts bucket */
    for (i = 0; i < header.script_count; i++) {
        zend_uint p_length = strlen(p);
        bucket = zend_accel_hash_update(&ZCSG(hash), p, p_length + 1, 0, ZFCSG(file_cached_scripts)+i);
        ZFCSG(file_cached_scripts)[i].incache_script_bucket = bucket;
        DEBUG1(INDEX, "script path:%s", p);
        p += p_length + 1;
    }

    CHECK_MARKER();

    /* scan the remaining (indirect) hash entries, data points to the corresponding file_cached_scripts bucket */
    for (i = 0; i < (header.max_hash_entry - header.script_count); i++) {
        zend_uint j = atoi(p);     /* referenced script number */
        zend_uint p_length;
        p += strlen(p) + 1;
        p_length = strlen(p) + 1;
        (void) zend_accel_hash_update(&ZCSG(hash), p, p_length, 1, ZFCSG(file_cached_scripts)[j].incache_script_bucket);
        DEBUG2(INDEX, "indirect path:%s refers to:%s", p, ZFCSG(file_cached_scripts)[j].incache_script_bucket->key);
        p += p_length;
    }

    CHECK_MARKER();

#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO && !defined(ZTS)

    /* scan interned strings added by module scripts */
    for (i = 0; i < header.interned_strings_count; i++) {
        int key_length;
        if ((signed) *p > 0 ) {
            key_length = *p++;
        } else {
            int shift = 0;
            key_length = 0;
            do {
                key_length |= ((int)(*p & 0x7f))<<shift;
                shift += 7;
            } while ((signed) *p++ < 0 );
        }
        (void) accel_new_interned_string(p, key_length, 0 TSRMLS_CC);
        DEBUG3(INDEX, "New interned[%u] (%u):%s", i, key_length, p);
        p += key_length;
    }

    CHECK_MARKER();
#endif    

    CHECK((p - obuf) == header.uncompressed_size);

//  DEBUG3(LOAD,"LOAD: Cache file %s restored to %p (%u bytes)", cache_path, addr, header.used);
    ZFCSG(fp) = fp; 
    ZFCSG(file_next_pos) = ZFCSG(file_zero_pos) = sizeof(header) + header.compressed_size;
	zend_shared_alloc_unlock(TSRMLS_C);    
    return 1;

error:
	zend_accel_error(ACCEL_LOG_WARNING, "internal failure file cache load: %s", errmsg);
    ZFCSG(file_cache_dirty) = 1;
    EFREE(cbuf);
    EFREE(ZFCSG(file_cached_scripts));
    fclose(fp);
	zend_shared_alloc_unlock(TSRMLS_C);
    return 0;
}

void zend_accel_close_file_cache(TSRMLS_D)
{ENTER(zend_accel_close_file_cache)
    char *tmp_filename = NULL;
    FILE *tmp_fp = NULL;
    struct stat sb = {0};
    size_t bytes_copied = 0;
    int sb_rtn;

    if (ZFCSG(file_cache_dirty)){
        if (ZFCSG(fp)) {
            fclose(ZFCSG(fp));
        }
        if (ZFCSG(fp_tmp)) {
            fclose(ZFCSG(fp_tmp));
        }
        EFREE(ZFCSG(file_cached_scripts));
        EFREE(ZFCSG(temp_cache_file));
        return;

    }
    if (!ZFCSG(fp_tmp)) {
        if (ZFCSG(fp)) {
            fclose(ZFCSG(fp));
        }
        EFREE(ZFCSG(file_cached_scripts));
        return;
    }

    CHECK(tmp_fp = open_temporary_file(TMP_FILE_PREFIX, &tmp_filename TSRMLS_CC));

    CHECK(write_index_to_file(tmp_fp));

    if(ZFCSG(fp)) {
        CHECK(fseek(ZFCSG(fp),ZFCSG(file_cached_scripts)[0].record_offset, SEEK_SET)==0);
        bytes_copied = copy_file(ZFCSG(fp), tmp_fp);
        fclose(ZFCSG(fp));
    }

    CHECK(fseek(ZFCSG(fp_tmp),0, SEEK_SET)==0);
    bytes_copied += copy_file(ZFCSG(fp_tmp), tmp_fp);

    CHECK(bytes_copied == ZFCSG(next_file_cache_offset));

    fclose(ZFCSG(fp_tmp)); ZFCSG(fp_tmp) = NULL;
    fclose(tmp_fp);

	sb_rtn = stat(ZCG(cache_path), &sb);

    if ((ZFCSG(fp) && sb_rtn == 0 &&
	     ZFCSG(fp_stat_block).st_ino   == sb.st_ino &&
         ZFCSG(fp_stat_block).st_dev   == sb.st_dev &&
         ZFCSG(fp_stat_block).st_mtime == sb.st_mtime) ||
        (!ZFCSG(fp) && sb_rtn == -1)) {
		(void) rename(tmp_filename, ZCG(cache_path));
	} else {
		(void) unlink(tmp_filename);
	}
	efree(tmp_filename);
    EFREE(ZFCSG(file_cached_scripts));
    EFREE(ZFCSG(temp_cache_file));

    return;

error:
    if (tmp_fp) {
        (void) fclose(tmp_fp);
    	efree(tmp_filename);
    }
    if (ZFCSG(fp_tmp)) {
        (void) fclose(ZFCSG(fp_tmp));
    }
	zend_accel_error(ACCEL_LOG_WARNING, "internal failure during file cache save");
}

static size_t copy_file(FILE *in, FILE *out)
{ENTER(copy_file)
    size_t bytes_copied = 0, bytes_read;
    void  *buffer = emalloc(CHUNK);

    while (!feof(in)) {
        bytes_read = fread(buffer, 1, CHUNK, in);
        bytes_copied += fwrite(buffer, 1, bytes_read, out);
    }
    efree(buffer);
    return bytes_copied;
}

static int write_index_to_file(FILE *fd)
{ENTER(write_index_to_file)
    char                   *obuf, *zbuf, *p;
    zend_uint               i, len;
	fc_index_header         header;
    zend_file_cache_record *r;
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO && !defined(ZTS)
    Bucket *interned_bucket;
    uint num_interned_strings;
#endif
    /* The cache contains op_arrays which reference entries from the zend_opcode_handlers vector, so
       it is specific to a given PHP build; so use the CRC of the vector as a build fingerprint */
    ZFCSG(ophandler_crc) = zend_adler32(ADLER32_INIT, (signed char *)zend_opcode_handlers, OPCODE_TABLE_SIZE * sizeof(void *));
    memset(&header, 0, sizeof(header));

    assert(ZCSG(hash).num_direct_entries == ZFCSG(file_cached_script_count));
    sprintf(header.fingerprint, FINGERPRINT_FORMAT, ZFCSG(ophandler_crc));
    header.script_count = ZFCSG(file_cached_script_count);
    header.max_include_paths_entry = ZCSG(include_paths).num_entries;
    header.max_hash_entry = ZCSG(hash).num_entries;
 
    /* Compute size of the file cache header: 1st the record vector + 4 markers */    
    len = (ZCSG(hash).num_direct_entries*sizeof(zend_file_cache_record))  + (4 * sizeof("****"));
    /*    + total in the include_paths key lengths */   
    for (i = 0; i < ZCSG(include_paths).num_entries; i++) {
        len += ZCSG(include_paths).hash_entries[i].key_length;
    }
    /*    + total in the hash key lengths */   
    for (i = 0; i < ZCSG(hash).num_entries; i++) {
        len += ZCSG(hash).hash_entries[i].key_length + 2;
    }
    /*    + the indirect entries also store a link index.  Use 8 char worst case */ 
    len += (ZCSG(hash).num_entries - ZCSG(hash).num_direct_entries)*8;

#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO && !defined(ZTS)
    /*    + the interned strings used in the modules */ 
    num_interned_strings = ZCSG(interned_strings).nNumOfElements - ZFCSG(interned_skip);
    interned_bucket = ZCSG(interned_strings).pListTail;

    for (i = 0; i < num_interned_strings ; i++) {
        uint string_length = interned_bucket->nKeyLength;
        interned_bucket = interned_bucket->pListLast;
        len += 1 + string_length;
        while (string_length > 0x7f) { /* count any extra multi-byte length bytes */
            string_length >>= 7;
            len++;
        }
    }    
    len += sizeof("****");

    assert(interned_bucket == ZFCSG(interned_base) || ZFCSG(interned_skip) == 0);

    header.interned_base_count    = ZFCSG(interned_skip);
    header.interned_strings_count = num_interned_strings;
    header.interned_base_tail     = (char *)ZFCSG(interned_base) - ZCSG(interned_strings_start);
# endif

    obuf = emalloc(len);

#define PUT_MARKER() memcpy(p,"****", 5); p+=5;

    for (i = 0, r = (zend_file_cache_record *) obuf; i < header.script_count; i++) {
        *r++ = ZFCSG(file_cached_scripts)[i].record;
    }
    p = (char *) r;

    PUT_MARKER();

    for (i = 0;  i < ZCSG(include_paths).num_entries; i++) {
        memcpy(p, ZCSG(include_paths).hash_entries[i].key, ZCSG(include_paths).hash_entries[i].key_length);
        DEBUG1(INDEX, "include path:%s", p);
        p += ZCSG(include_paths).hash_entries[i].key_length;
        *p++ = 0;
        *p++ = 0;
    }

    PUT_MARKER();

    for (i = 0; i < ZFCSG(file_cached_script_count); i++) {
        zend_accel_hash_entry *bucket = ZFCSG(file_cached_scripts)[i].incache_script_bucket;
        memcpy(p, bucket->key, bucket->key_length);
        DEBUG1(INDEX, "script path:%s", p);
        p += bucket->key_length;
    }

    PUT_MARKER();

    /* scan the remaining (indirect) hash entries, data points to the corresponding file_cached_scripts bucket */
    for (i = 0; i < ZCSG(hash).num_entries; i++) {
        zend_accel_hash_entry *bucket = ZCSG(hash).hash_entries + i;
        if (bucket->indirect) {
            void *data = ((zend_accel_hash_entry *) bucket->data)->data;
            zend_uint ndx = (zend_file_cached_script *)data - ZFCSG(file_cached_scripts);
            if (ndx >= ZFCSG(file_cached_script_count)) {
                ndx = ((zend_persistent_script *)data)->dynamic_members.file_cache_index;
            }
            sprintf(p,"%u",ndx);
            p += strlen(p)+1;
            memcpy(p, bucket->key, bucket->key_length);
            DEBUG1(INDEX, "indirect path:%s", p);
            p += bucket->key_length;         
        }
    }

    PUT_MARKER();

#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO && !defined(ZTS)   
    /* scan interned strings added by module scripts */
    for (i = 0, interned_bucket = ZFCSG(interned_base)->pListNext; i < num_interned_strings; i++) {
        uint l = interned_bucket->nKeyLength;

        while (l > 0x000000007f) {
            *p++ = ((char) (l & 0x000000007f)) | 0x80 ;
            l >>= 7;
        }
        *p++ = l;
        DEBUG3(INDEX, "Interned[%u] (%u):%*2$s", i, interned_bucket->nKeyLength, interned_bucket->arKey);
        memcpy(p, interned_bucket->arKey, interned_bucket->nKeyLength);
        p += interned_bucket->nKeyLength;
        interned_bucket = interned_bucket->pListNext;
    }

    PUT_MARKER();
#endif
	header.uncompressed_size       = p - obuf;

    CHECK(header.uncompressed_size <= len);

    CHECK((header.compressed_size = cache_compress(obuf, &zbuf, header.uncompressed_size)) > 0);

    DEBUG5(INDEX, "Cache File header - CS:%u US:%u SC:%u #I:%u #H:%u",  header.compressed_size,
                  header.uncompressed_size, header.script_count, 
                  header.max_include_paths_entry, header.max_hash_entry);
# if (ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO) && !defined(ZTS)
    DEBUG3(INDEX, "Cache File header - #IBC:%u #IC:%u ICO:%u",  header.interned_base_count,
                  header.interned_strings_count, header.interned_base_tail);
#endif    

    CHECK(fwrite(&header, 1, sizeof(header),fd) == sizeof(header));
    CHECK(fwrite(zbuf, 1, header.compressed_size, fd) == header.compressed_size);
    efree(obuf);
    efree(zbuf);

    return 1;

error:
	zend_accel_error(ACCEL_LOG_WARNING, "internal failure file index write");
    ZFCSG(file_cache_dirty) = 1;
    EFREE(obuf);
    EFREE(zbuf);
    return 0;
}


static void resize_file_cached_script_vec(void)
{ENTER(resize_file_cached_script_vec)
    /* handle growth of the FC script vector */
    zend_file_cached_script *old_vec = ZFCSG(file_cached_scripts);
    zend_file_cached_script *old_vec_max = old_vec + ZFCSG(file_cached_script_count);
    zend_uint i;

    if (ZFCSG(file_cached_scripts)) {
        ZFCSG(file_cached_script_alloc) += SCRIPT_VEC_HEADROOM;
        ZFCSG(file_cached_scripts) = erealloc(ZFCSG(file_cached_scripts), 
                                              ZFCSG(file_cached_script_alloc)*sizeof(zend_file_cached_script));
        if (ZFCSG(file_cached_scripts) != old_vec) {
           /* The ZCSG(hash) entries can point to vec entries, and if so each entry needs to be 
              relocated to corresponding entry in the newly allocated vector */
            for (i = 0; i<ZCSG(hash).num_entries; i++) {
                char *ptr = (char *) &(ZCSG(hash).hash_entries[i].data);
                if (!ZCSG(hash).hash_entries[i].indirect &&
                    ptr >= (char *) old_vec && ptr < (char *)old_vec_max) {
                    zend_uint j = (zend_file_cached_script *)ptr - old_vec;
                    ZCSG(hash).hash_entries[i].data = ZFCSG(file_cached_scripts)+j;
                }
            }
        }
    } else {
        ZFCSG(file_cached_script_alloc) = SCRIPT_VEC_HEADROOM;
        ZFCSG(file_cached_scripts) = emalloc(SCRIPT_VEC_HEADROOM*sizeof(zend_file_cached_script));
    }
}

void zend_accel_save_module_to_file(zend_accel_hash_entry *bucket TSRMLS_DC)
{ENTER(zend_accel_save_module_to_file)
    zend_persistent_script  *script  = (zend_persistent_script *) bucket->data;
    char                    *module_addr = script->mem;
    zend_uint                ndx = ZFCSG(file_cached_script_count)++;
    zend_file_cached_script  entry;
    char                    *zbuf = NULL, *rbvec = NULL, *interned_vec = NULL;
              
    if (ZFCSG(file_cache_dirty) || bucket->indirect) { /* ignore file cache once flagged as dirty */
        return;
    }

    if (ndx >= ZFCSG(file_cached_script_alloc)) {
        resize_file_cached_script_vec();
    }

    CHECK(ZFCSG(fp_tmp) || 
          (ZFCSG(fp_tmp) = open_temporary_file(TMP_FILE_PREFIX, &(ZFCSG(temp_cache_file)) TSRMLS_CC)));

    script->dynamic_members.file_cache_index = ndx;
    entry.incache_script_bucket    = bucket;
    entry.record_offset            = ZFCSG(next_file_cache_offset);
	entry.record.uncompressed_size = script->size;
    entry.record.script_offset     = (char *)script - module_addr;
    entry.record.reloc_bvec_size   = make_block_rbvec(module_addr, script->size, &rbvec);

    CHECK((entry.record.compressed_size = cache_compress(module_addr, &zbuf, script->size)) > 0);

    CHECK(fwrite(zbuf, 1, entry.record.compressed_size, ZFCSG(fp_tmp))==entry.record.compressed_size);
    ZFCSG(next_file_cache_offset) += entry.record.compressed_size + entry.record.reloc_bvec_size;  
    CHECK(fwrite(rbvec, 1,entry.record.reloc_bvec_size, ZFCSG(fp_tmp))==entry.record.reloc_bvec_size);
    efree(zbuf); zbuf = NULL;

# if (ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO) && !defined(ZTS)
// TODO: Interned string support
//   if (zbuf_size < compressBound(entry.record.full_interned_size) {
//        zbuf = erealloc(entry.record.full_interned_size);
//    }
//    CHECK((entry.record.compressed_interned_size = cache_compress(module_addr, &zbuf, entry.record.full_interned_size)) > 0);
//    CHECK(fwrite(zbuf, 1, zbuf_length, ZFCSG(fp_tmp))==zbuf_length);
//    ZFCSG(next_file_cache_offset) += entry.record.compressed_interned_size;
//    efree(zbuf); zbuf = NULL:
# endif

    relocate_script(&entry, module_addr, rbvec, interned_vec);  /* undo relocation side-effects */
    ZFCSG(file_cached_scripts)[ndx] = entry;

    return;

error:
	zend_accel_error(ACCEL_LOG_WARNING, "internal failure during cache write of %s", bucket->key);
    ZFCSG(file_cache_dirty) = 1;
    EFREE(zbuf);
    EFREE(rbvec);
    EFREE(interned_vec);
    fclose(ZFCSG(fp));
    if (ZFCSG(fp_tmp)) {
        fclose(ZFCSG(fp_tmp));
    }
}

void zend_accel_load_module_from_file(zend_uint ndx, zend_accel_hash_entry *bucket TSRMLS_DC)
{ENTER(zend_accel_load_module_from_file)
    zend_file_cached_script *script = ZFCSG(file_cached_scripts) + ndx;
    char *buf = NULL;
    char *obuf, *reloc_bvec, *interned = NULL;
    zend_uint buf_len;
    zend_ulong offset, obuf_len;

    if (ZFCSG(file_cache_dirty)) { /* ignore file cache once flagged as dirty */
        return;
    }
    offset = script->record_offset;
	if (offset != ZFCSG(file_next_pos)) {
		CHECK(fseek(ZFCSG(fp), offset, SEEK_SET)==0);
	}

    buf_len = script->record.compressed_size +
              script->record.reloc_bvec_size;
    buf = emalloc(buf_len);
    CHECK(fread((void *) buf, 1, buf_len, ZFCSG(fp)) == buf_len);
    ZFCSG(file_next_pos) = offset + buf_len;

    obuf_len = script->record.uncompressed_size;

	zend_shared_alloc_lock(TSRMLS_C);
    obuf = zend_shared_alloc(obuf_len);

    CHECK(cache_decompress(buf, obuf, script->record.compressed_size, script->record.uncompressed_size));
    reloc_bvec = buf + script->record.compressed_size;

#if (ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO) && !defined(ZTS)
//    interned = emalloc(script->uncompressed_interned_size);
//    CHECK(cache_decompress(reloc_bvec+script->reloc_bvec_size, interned, 
//                           script->compressed_interned_size, script->uncompressed_interned_size));
#endif
    bucket->data = obuf + script->record.script_offset;
    relocate_script(script, obuf, reloc_bvec, interned);
    efree(buf);
	zend_shared_alloc_unlock(TSRMLS_C);
	return;

error:
	zend_accel_error(ACCEL_LOG_WARNING, "internal failure file cache module: %s", 
                                        bucket->key);
    ZFCSG(file_cache_dirty) = 1;
    EFREE(buf);
    EFREE(ZFCSG(file_cached_scripts));
    fclose(ZFCSG(fp));
    ZFCSG(fp)=NULL;
	zend_shared_alloc_unlock(TSRMLS_C);
    return;
}

void zend_accel_file_cache_clear_file_cache(void)
{ENTER(zend_accel_file_cache_clear_file_cache)
}

/* generate_cache_name() is called lazily at first module access because the SAPI context is then
   available to decode the requested filename. Native PCRE is used
   here, as the PHP PCRE functions require components of the Zend execution environment which are
   not initialised at this point. */ 
static char *generate_cache_name(TSRMLS_D)
{ENTER(generate_cache_name)

    char *filt       = ZCG(accel_directives).cache_pattern;
    char *repl       = ZCG(accel_directives).cache_file;
    char *filename   = SG(request_info).path_translated;
    char *cache_path = NULL;
    pcre *re         = NULL;
    pcre_extra *rex  = NULL;
    const char *error;
    int error_offset, n_pats; 

    /* Only do replacement processing if the cache parameters are set. */ 
    if (!filename || !repl || repl[0] =='\0') { 
        return NULL;
    } 
    if (!filt || filt[0] =='\0') { 
        int l=strlen(repl);
        cache_path = malloc(l + 1);
        strcpy(cache_path, repl);
        return cache_path;
    } 

    if ((re = pcre_compile(filt, PCRE_UTF8, &error, &error_offset, NULL)) == NULL || 
        (rex = pcre_study(re, 0, &error)) == NULL ||
        pcre_fullinfo(re, rex, PCRE_INFO_CAPTURECOUNT, &n_pats) < 0 ||
        n_pats > 10)  {

        zend_accel_error(ACCEL_LOG_WARNING, "Invalid cache pattern; Caching is suppressed.");

    } else { /* pattern compiled so we're good to go */
        int ovector[30];
        if ((n_pats = pcre_exec(re, rex, filename, strlen(filename),
                                0, 0, ovector, 30)) <= 0) {
            zend_accel_error(ACCEL_LOG_WARNING, 
                         "Cache pattern failed to match %s; Caching is suppressed.", filename);
       } else { /* pattern executed against filename so map $0..$9 to str + sub1 .. sub9 */
            char  tmp_path[MAXPATHLEN+1];
            char *p = repl; 
            char *q = tmp_path, *qend = tmp_path + MAXPATHLEN;
            int   i;
            int   n = strlen(p); 
            int   mode = 0;    /* 1 = last was \ escape; 2 last was $; 0 otherwise */
            /* construct replacement filename */
            for (i = 0; i<n && q < qend; i++, p++) {
                if (*p == '\\') {
                    if (mode==0) {
                        mode = 1;
                    } else {
                        *q++ = '\\';
                        mode = 0;
                    }
                } else if (*p == '$' && mode != 1 && p[1]>='0' && p[1]<= '9' ) {
                    mode = 2;
                } else if (mode == 2) {
                    int pat_no = (*p - '0');
                    if (pat_no < n_pats) {
                        int rc = pcre_copy_substring(filename, ovector, n_pats, pat_no, 
                                                     q, qend-q);
                        if (rc < 0) {
                            q = qend+1;
                            break;
                        } else {
                            q += rc;
                        }
                    }
                    mode = 0;
                } else {
                    if((*q++ = *p) == 0) {
                        break;
                    }
                    mode = 0;
                }
            }
            if (q > qend) {
                zend_accel_error(ACCEL_LOG_WARNING, 
                             "Cache filename too long; Caching is suppressed.");
            } else {
                i = q - tmp_path;
                cache_path = malloc(i + 1);
                strncpy(cache_path, tmp_path, i);
            }
        }
    }
    if (re) {
        pcre_free(re);
    }
    if (rex) {
        pcre_free(rex);
    }
        
    return cache_path;
}

/* {{{ make_block_rbvec 
   BOTCH WARNING: This code was originally a pull from LPC, but restyled in the ZendOptimizer 
   coding style. The LPC version used intelligent taging to identify valid pointers for relocation. 
   This version simply identifies any size_t value in the address range of the block or the interned
   pool as an block-internal pointer. This works for now on 64bit architectures as a block addr is
   typically a pretty high 64bit value (eg. 0x00007f90cbdf3000) which won't be in the block unless
   it is an internal pointer. This will need to be fixed in the next commit point. 
   It also exploits the fact that all targets are size_t aligned */
static zend_uint make_block_rbvec(void *addr, zend_uint size, char **rbvec)
{ENTER(make_block_rbvec)
    void **p, **lastp, **pend;
    unsigned char *reloc_bvec, *q;
    zend_uint   delta, cnt = 1;

    /* 1st pass to compute size of the relocation vector */
    for (p = (void **)addr, lastp = p, pend = p + (size / sizeof(void*)); p < pend; p++) {
        if (!*p) continue;
        delta = 0;
        if ( ((size_t)((char *)*p - (char *)addr)) < size
#if (ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO) && !defined(ZTS)
             || IS_INTERNED((char *) *p)
#endif
           ) {
            cnt++;
            /* add extra bytes when multi-byte sequences are used */
            for (delta = (zend_uint) (p - lastp); delta>=0x80; delta >>= 7, cnt++) { }
            lastp = p;
        }
    }

	reloc_bvec = (unsigned char *) malloc(cnt);
	if (!reloc_bvec) {
		zend_accel_error(ACCEL_LOG_ERROR, "malloc() failed");
		return 0;
	}

    /* 2nd pass to generate the relocation byte vector */
    for (p = (void **)addr, q = reloc_bvec, lastp = p, pend = p + (size / sizeof(void*)); 
         p < pend; p++) {
        /* The target if in the module or interned pool is itself size_t aligned, so the PIC
           form is the size_t units from the base module addr / interned pool start. */
        if ( ((size_t)((char *)*p - (char *)addr)) < size ) {
            *p    = (void *) (*(size_t **)p - (size_t *)addr); /* convert ptr to offset */
#if (ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO) && !defined(ZTS)
        } else if (IS_INTERNED(*(char **) p)) {
            *p    = (void *) (ADDR_HI_SET + (*(size_t **)p - (size_t *)ZCSG(interned_strings_start)));
#endif
        } else {
            continue;
        }
        delta = (zend_uint) (size_t) (p - lastp);
        if (delta <= 0x7f) { /* the typical case */
            *q++ = (unsigned char) delta;
        } else {             /* handle the multi-byte cases */
           /* Emit multi-bytes lsb first with 7 bits sig; high-bit set to indicate follow-on. */
            *q++ = (unsigned char)(delta & 0x7f) | 0x80;
            if (delta <= 0x3fff) {
                *q++ = (unsigned char)((delta>>7)  & 0x7f);
            } else if (delta <= 0x1fffff) {
                *q++ = (unsigned char)((delta>>7)  & 0x7f) | 0x80;
                *q++ = (unsigned char)((delta>>14) & 0x7f);    
            } else if (delta <= 0xfffffff) {
                *q++ = (unsigned char)((delta>>7)  & 0x7f) | 0x80;
                *q++ = (unsigned char)((delta>>14) & 0x7f) | 0x80;
                *q++ = (unsigned char)((delta>>21) & 0x7f);    
            } else {
                zend_accel_error(ACCEL_LOG_ERROR, 
                                 "Fatal: invalid offset %u found during internal copy", delta);
                return 0;
            }
        }
        lastp = p;
    }
    *q++ = '\0'; /* add an end marker so the reverse process can terminate */
    assert((zend_uchar *)q == reloc_bvec+cnt);
    *rbvec = (char *)  reloc_bvec;
    return cnt;
}
/* }}} */

/* {{{ relocate_sma. The relocation byte vector (rbvec) contains the byte offset (in size_t units)
       of each * pointer in the SMA to be relocated. As these pointers are a lot denser than every *
       127 longs (1016 bytes), the encoding uses a simple high-bit multi-byte escape to * encode
       exceptions. Also note that 0 is used as a terminator excepting that the first * entry can
       validly be '0'. */
// TODO: Add interned vector processing
static void relocate_script(zend_file_cached_script *entry, char *memory_area, char *rbvec, char *interned)
{ENTER(relocate_script)
    zend_persistent_script *script = (zend_persistent_script *) entry->incache_script_bucket->data;
    size_t         addr_offset     = (size_t) memory_area;
    size_t        *q               = (size_t *) memory_area;
    size_t         max_qval        = script->size;
    unsigned char *p               = (unsigned char *) rbvec;
   /* Use a do {} while loop because the first byte offset can by zero; any other is a terminator */
    do {
        if (p[0]<128) {         /* offset <1K the typical case */
            q += *p++;
        } else if (p[1]<128) {  /* offset <128Kb */
            q += (zend_uint)(p[0] & 0x7f) + (((zend_uint)p[1])<<7);
            p += 2;
        } else if (p[2]<128) {  /* offset <16Mb */
            q += (zend_uint)(p[0] & 0x7f) + ((zend_uint)(p[1] & 0x7f)<<7) + (((zend_uint)p[2])<<14);
            p += 3;
        } else if (p[3]<128) {  /* offset <2Gb Ho-ho */
            q += (zend_uint)(p[0] & 0x7f)      + ((zend_uint)(p[1] & 0x7f)<<7) + 
                ((zend_uint)(p[2] & 0x7f)<<14) + (((zend_uint)p[3])<<21);
            p += 4;
        }
        if (*q < max_qval) {
            *q = (size_t) ((size_t *) addr_offset + *q);
            continue;
        }
#if (ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO) && !defined(ZTS)
        if (*q & (size_t) ADDR_HI_SET) {
            *q = (size_t)((size_t *)ZCSG(interned_strings_start) + (*q ^ ADDR_HI_SET));
            continue;
        }
#endif
        zend_accel_error(ACCEL_LOG_ERROR, 
                         "Relocation error: invalid offset %p at offset %08lx in SMA", 
                         *((void **)q), (char *)q - (char *)addr_offset);
    } while (*p != '\0');
   
    assert((char *)q < memory_area + max_qval);
}
// TODO: Need to implement Windows version of this.
static FILE *open_temporary_file(char* prefix, char **name TSRMLS_DC)
{ENTER(open_temporary_file)
    char *tmp_name = emalloc(strlen(ZCG(cache_path)) + strlen(prefix) + 3 + 8 + 6);
    FILE *tmp_fd;
    char *t;
	int tmp_file;

    strcpy(tmp_name, ZCG(cache_path));
    t = dirname(tmp_name);
    if (tmp_name != t) {
        strcpy(tmp_name, t);
    }

	sprintf(tmp_name+strlen(tmp_name), "%sXXXXXX", prefix);
	tmp_file = mkstemp(tmp_name);

	if (tmp_file >0 && (tmp_fd = fdopen(tmp_file, "wbx")) != NULL) {
        *name = tmp_name;
        return tmp_fd;
    }         

 	zend_accel_error(ACCEL_LOG_ERROR, "Unable to create temp file: %s", tmp_name);
    efree(tmp_name);
	return NULL;
}

int cache_compress(const char* source, char** dest, int source_size)
{ENTER(cache_compress)
    int dest_size;
    int algo = ZCG(accel_directives).compression_algo;
    TSRMLS_FETCH();

    if (algo == 1) { /* Standard zlib */
        zend_ulong dest_length = dest_size = compressBound(source_size);
	    *dest = emalloc(dest_size);

	    if (compress(*(unsigned char **)dest, &dest_length, (unsigned char *)source, source_size) == Z_OK) {
            return (int) dest_length;
        } 
    } else if (algo == 2 || algo == 3) { /* LZ4 and LZ4HC compress */
        int dest_length;
        dest_size = LZ4_compressBound(source_size);
	    *dest = emalloc(dest_size);
        dest_length = algo == 2 ? LZ4_compress(source, *dest, source_size) :
                                  LZ4_compressHC(source, *dest, source_size);
        if (dest_length) {
            return dest_length;
        }
    }

    efree(*dest);
    *dest = NULL;
    return 0;
}

int cache_decompress(const char* source, char* dest, int source_size, int dest_size)
{ENTER(cache_decompress)
    TSRMLS_FETCH();

    if (!source || !dest || !source_size || !dest_size) {
        return 0;
    }

    if (ZCG(accel_directives).compression_algo == 1) { /* Standard zlib */
        zend_ulong dest_length = dest_size;

        if (uncompress((unsigned char *)dest, &dest_length, (unsigned char *)source, source_size) == Z_OK &&
            dest_size > 0 && dest_length == (unsigned) dest_size) {
            return 1;
        }
    } else if (ZCG(accel_directives).compression_algo == 2 ||
               ZCG(accel_directives).compression_algo == 3) { /* LZ4 & LZ4HC compress */
        if (dest_size == LZ4_decompress_safe(source, dest, source_size, dest_size)) {
            return 1;
        }
    }
    return 0;
}

#endif /* OPCACHE_ENABLE_FILE_CACHE */

