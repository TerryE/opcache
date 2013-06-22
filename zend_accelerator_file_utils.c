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
#include "tsrm_virtual_cwd.h"
#include "ext/standard/php_string.h"

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
#include "zend_vm.h"

#include "ext/standard/info.h"
#include "ext/standard/file.h"

#include <string.h>
#include <errno.h>


/* Notes:

   1) Even thought the will only ever by one thread for CLI and GCI processes, CLI persistance is
      still TSRM enabled to allow CLI based testing of TSRM builds.

   2) TODO: add compile-time checks only to enable OPCACHE_ENABLE_FILE_CACHE when PCRE is available.

   3) TODO: GCC on ZFCSG(in_cachename)

   4) TODO: zend_accel_save_sma() runs as part of image rundown by which time a lot of PHP services 
            have run down.  might be worth bumping its hook back to request shutdown to make life 
            simpler.
*/
#define CHUNK 65536
#define TMP_FILE_PREFIX ".OPcache."
#define CHECK(p) if(!(p)) goto error
#define EFREE(p) if(p) {efree(p); p = NULL;}

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
#define FLAG_MASK       (SIZEOF_SIZE_T-1)
#ifdef ACCEL_DEBUG
#  define BREAK_HERE(p) break_here((char **)p);
#else
#  define BREAK_HERE(p) zend_accel_error(ACCEL_LOG_ERROR, "invalid reference at %p", p);
#endif

#define ALIGNED_PTR_MASK ~(size_t)(SIZEOF_SIZE_T-1)
#define RELOCATE_PI(type,p) p = (type *) (((size_t)(p) + (size_t)(&p)) & ALIGNED_PTR_MASK); \
   DEBUG3(RELR, "Making (" #type "*) %p position absolute %p at line %u", &p, p, __LINE__)
#define RELOCATE_PI_NZ(type,p) if (p) {RELOCATE_PI(type,p);}
#define IS_INTERNAL(s) (((s) >= ZFCSG(module_base)) && ((s) < ZFCSG(module_end)))
  
/* Function call used as error hook for debugging */ 
static void break_here(char **p){
    IF_DEBUG(ERROR_ON_BREAK_HERE) {
		if(!fork()) { 
			abort(); /* Produce a crash dump for further analysis */
		} 
        zend_accel_error(ACCEL_LOG_ERROR, "invalid reference at %p", p);
    } else {
    	DEBUG2(RELR, "invalid reference at %p to %p ", p, *p);
    }
}


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
static void      resize_file_cached_script_vec(void);
# if (ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO) && !defined(ZTS)
static zend_uint make_interned_vars(zend_file_cached_script *script, char **interned_vec);
#endif
static FILE     *open_temporary_file(char* prefix, char **name TSRMLS_DC);
static int       write_index_to_file(FILE *fd);
static size_t    copy_file(FILE *in, FILE *out);
static void      cleanup_cache_files(void);
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

    SET_TIMER(NDXLOAD);
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO && !defined(ZTS)
    ZFCSG(interned_skip) = ZCSG(interned_strings).nNumOfElements;
    ZFCSG(interned_base) = ZCSG(interned_strings).pListTail;
#endif

    ZFCSG(in_cachename) = generate_cache_name(TSRMLS_C);
    if (!ZFCSG(in_cachename)) {
        /* no cache file so fail through to default (no file cache) processing */
        zend_accel_error(ACCEL_LOG_INFO, "LOAD: no cache file specified");
        ZSMMG(use_file_cache) = 0;
        return 0;
    }

    /* The cache contains op_arrays which reference entries from the zend_opcode_handlers vector, so
       it is specific to a given PHP build; so use the CRC of the vector as a build fingerprint */
    ZFCSG(ophandler_crc) = zend_adler32(ADLER32_INIT, (signed char *)zend_opcode_handlers, OPCODE_TABLE_SIZE * sizeof(void *));

    memset(&header, 0, sizeof(header));
    sprintf(header_fingerprint, FINGERPRINT_FORMAT, ZFCSG(ophandler_crc));
/// TODO: need to realpath this
    if (ZFCSG(in_cachename)[0] != '/' ||
        (fp = fopen(ZFCSG(in_cachename), "rb")) == NULL) {
        /* cache isn't a valid file or we can't open it so again fail through */ 
        zend_accel_error(ACCEL_LOG_INFO, "LOAD: cache file %s does not exist. Creating new file.", ZFCSG(in_cachename));
        return 1;
    }

    ZFCSG(in_fp) = fp;

    SET_TIMER(CACHEREAD);

    if (fread((void *) &header, 1, sizeof(header), fp) != sizeof(header)
        || memcmp(header_fingerprint, header.fingerprint, FINGERPRINT_SIZE) != 0 
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO && !defined(ZTS)
        || ZFCSG(interned_skip) != header.interned_base_count
        || ZFCSG(interned_base) != (Bucket*)(ZCSG(interned_strings_start) + header.interned_base_tail)
#endif
        ) {
    	zend_accel_error(ACCEL_LOG_WARNING, "Fingerprint mismatch on File cache", errmsg);
        ZFCSG(file_cache_dirty) = 1;
        ZSMMG(use_file_cache) = 0;
        cleanup_cache_files();
        return 0;
    }

    DEBUG5(INDEX, "cache file header - CS:%u US:%u SC:%u #I:%u #H:%u",  (int) sizeof(header) + header.compressed_size, 
                  header.uncompressed_size, header.script_count, 
                  header.max_include_paths_entry, header.max_hash_entry);
# if (ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO) && !defined(ZTS)
    DEBUG3(INDEX,"cache file header - #IBC:%u #IC:%u ICO:%u",  header.interned_base_count,
                 header.interned_strings_count, header.interned_base_tail);
#endif    

    errmsg = "unable to stat file";
	CHECK(fstat(fileno(fp), &ZFCSG(fp_stat_block)) == 0);

    cbuf = emalloc(header.compressed_size);
    errmsg = "unable to read index";
    CHECK(fread((void *) cbuf, 1, header.compressed_size, fp) == header.compressed_size);

    COLLECT_TIMER(CACHEREAD);

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
        DEBUG2(INDEX, "script path(%u):%s", i, p);
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
        DEBUG3(INTERN, "new[%u] (%u):%s", i, key_length, p);
        p += key_length;
    }

    CHECK_MARKER();
#endif    

    CHECK((p - obuf) == header.uncompressed_size);

    ZFCSG(file_next_pos) = ZFCSG(file_zero_pos) = sizeof(header) + header.compressed_size;
	zend_shared_alloc_unlock(TSRMLS_C);    
    COLLECT_TIMER(NDXLOAD);
    return 1;

error:
	zend_accel_error(ACCEL_LOG_WARNING, "internal failure file cache load: %s", errmsg);
	zend_shared_alloc_unlock(TSRMLS_C);
    ZFCSG(file_cache_dirty) = 1;
    EFREE(cbuf);
    cleanup_cache_files();
    ZSMMG(use_file_cache) = 0;
    COLLECT_TIMER(NDXLOAD);
    return 0;
}

void zend_accel_close_file_cache(TSRMLS_D)
{ENTER(zend_accel_close_file_cache)
    struct stat sb = {0};
    off_t bytes_copied = 0, bytes_copied2 = 0;
    int sb_rtn;

    if (ZFCSG(file_cache_dirty) || !ZFCSG(tmp_fp) || ZFCSG(pid) != getpid()) {
        cleanup_cache_files();
        EFREE(ZFCSG(file_cached_scripts));
        return;
    }

    SET_TIMER(CACHEWRITE);

	ZFCSG(new_fp) = open_temporary_file(TMP_FILE_PREFIX, &ZFCSG(new_cachename) TSRMLS_CC);
	if (!ZFCSG(new_fp)) {
        cleanup_cache_files();
        EFREE(ZFCSG(file_cached_scripts));
        return; /* no need to log error; open_temporary_file() has already done this */
    }

    CHECK(write_index_to_file(ZFCSG(new_fp)));

    if(ZFCSG(in_fp)) {
        CHECK(fseek(ZFCSG(in_fp),ZFCSG(file_cached_scripts)[0].record_offset, SEEK_SET)==0);
        bytes_copied = copy_file(ZFCSG(in_fp), ZFCSG(new_fp));
        DEBUG1(LOAD, "%u bytes copied from old cache to new", (int) bytes_copied);
    }

    CHECK(fseek(ZFCSG(tmp_fp),0, SEEK_SET)==0);
    bytes_copied2 = copy_file(ZFCSG(tmp_fp), ZFCSG(new_fp));
    DEBUG1(LOAD, "%u bytes copied from tmp cache to new", (int) bytes_copied2);
    bytes_copied += bytes_copied2;

    CHECK(bytes_copied == ZFCSG(next_file_cache_offset) - ZFCSG(file_cached_scripts)[0].record_offset);

    /* stat current cache.  If either previous cache doesn't exist or it does and hasn't already 
       been overwritten by a parallel process do move */
	sb_rtn = stat(ZFCSG(in_cachename), &sb);   
    if (!ZFCSG(in_fp) && sb_rtn) {
        (void) fclose(ZFCSG(new_fp));
        ZFCSG(new_fp) = NULL;
/// TODO: This can fail due to a share violation on Win32
		(void) rename(ZFCSG(new_cachename), ZFCSG(in_cachename));

    } else if (ZFCSG(in_fp) && !sb_rtn &&
               ZFCSG(fp_stat_block).st_ino   == sb.st_ino &&
               ZFCSG(fp_stat_block).st_dev   == sb.st_dev &&
               ZFCSG(fp_stat_block).st_mtime == sb.st_mtime) {
        (void) fclose(ZFCSG(in_fp));
        (void) fclose(ZFCSG(new_fp));
        ZFCSG(in_fp) = ZFCSG(new_fp) = NULL;
/// TODO: This can fail due to a share violation on Win32
		(void) rename(ZFCSG(new_cachename), ZFCSG(in_cachename));
	} else {
		zend_accel_error(ACCEL_LOG_WARNING, "unable to create cache file %s", ZFCSG(in_cachename));
		ZFCSG(file_cache_dirty) = 1;
	}
    cleanup_cache_files();
    EFREE(ZFCSG(file_cached_scripts));

    COLLECT_TIMER(CACHEWRITE);

    return;

error:
    cleanup_cache_files();
    EFREE(ZFCSG(file_cached_scripts));
	zend_accel_error(ACCEL_LOG_ERROR, "internal failure during file cache save");
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

#define CLEANUP_FILE(f) \
    if (ZFCSG(f ## _fp)) { \
        (void) fclose(ZFCSG(f ## _fp)); \
        (void) unlink(ZFCSG(f ## _cachename)); \
        ZFCSG(f ## _fp) = NULL; \
    }
/* It's just easier to have a common files cleanup which handles all this cleanup */
static void cleanup_cache_files(void)
{ENTER(cleanup_cache_files);
    CLEANUP_FILE(tmp);
    CLEANUP_FILE(new);
    if (ZFCSG(file_cache_dirty)) {
        CLEANUP_FILE(new);
    } else if (ZFCSG(in_fp)) {
        (void) fclose(ZFCSG(in_fp));
        ZFCSG(in_fp) = NULL;
    }
    EFREE(ZFCSG(in_cachename));
    EFREE(ZFCSG(tmp_cachename));
    EFREE(ZFCSG(new_cachename));
}

static int write_index_to_file(FILE *fd)
{ENTER(write_index_to_file)
    char                   *obuf = NULL, *zbuf = NULL, *p;
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
        len += ZCSG(include_paths).hash_entries[i].key_length + 2;
    }
    /*    + total in the hash key lengths */   
    for (i = 0; i < ZCSG(hash).num_entries; i++) {
        len += ZCSG(hash).hash_entries[i].key_length;
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
        DEBUG3(INTERN, "copy[%u] (%u):%*2$s", i, interned_bucket->nKeyLength, interned_bucket->arKey);
        memcpy(p, interned_bucket->arKey, interned_bucket->nKeyLength);
        p += interned_bucket->nKeyLength;
        interned_bucket = interned_bucket->pListNext;
    }

    PUT_MARKER();
#endif
	header.uncompressed_size       = p - obuf;

    CHECK(header.uncompressed_size <= len);

    CHECK((header.compressed_size = cache_compress(obuf, &zbuf, header.uncompressed_size)) > 0);

    DEBUG5(INDEX, "cache file header - CS:%u US:%u SC:%u #I:%u #H:%u",  (int) sizeof(header) + header.compressed_size,
                  header.uncompressed_size, header.script_count, 
                  header.max_include_paths_entry, header.max_hash_entry);
# if (ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO) && !defined(ZTS)
    DEBUG3(INDEX, "cache file header - #IBC:%u #IC:%u ICO:%u",  header.interned_base_count,
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

    if (!ZFCSG(file_cached_scripts)) {
        ZFCSG(file_cached_script_alloc) = SCRIPT_VEC_HEADROOM;
        ZFCSG(file_cached_scripts) = emalloc(SCRIPT_VEC_HEADROOM*sizeof(zend_file_cached_script));
    } else {
		zend_file_cached_script *old_vec = ZFCSG(file_cached_scripts);
		zend_uint i;

        ZFCSG(file_cached_script_alloc) += SCRIPT_VEC_HEADROOM;
        ZFCSG(file_cached_scripts) = erealloc(ZFCSG(file_cached_scripts), 
                                              ZFCSG(file_cached_script_alloc)*sizeof(zend_file_cached_script));
		/* The cached script record points to the corresponding ZCSG(hash) bucket. If the modules is
		   still to be loaded from the file cache, the bucket data points back to the cached script
		   record, and this pointer need to be updated to point to the new vector location. */
		for (i = 0; i <  ZFCSG(file_cached_script_count) - 1; i++) {
		    zend_accel_hash_entry *bucket = ZFCSG(file_cached_scripts)[i].incache_script_bucket;
	        zend_uint ndx = (zend_file_cached_script *)(bucket->data) - old_vec;
	        if (ndx < ZFCSG(file_cached_script_count)) {
				bucket->data = ZFCSG(file_cached_scripts) + ndx;
			}
		}
    }
}

void zend_accel_save_module_to_file(zend_accel_hash_entry *bucket TSRMLS_DC)
{ENTER(zend_accel_save_module_to_file)
    zend_persistent_script  *script  = (zend_persistent_script *) bucket->data;
    char                    *module_addr = script->mem;
    zend_uint                ndx = ZFCSG(file_cached_script_count)++;
    zend_file_cached_script  entry;
    char                    *zbuf = NULL, *interned_vec = NULL;
    zend_uchar              *rbvec = NULL;
              
    if (ZFCSG(file_cache_dirty) || bucket->indirect) { /* ignore file cache once flagged as dirty */
        return;
    }

	/* Save the pid at first call to the save routine. If the process has forked since the first
	   call, turn off cache write in the child and treat the filecache as R/O. Note that the modules
	   unique to the child can still be cached because the first request will prime the cache for
	   the parent scripts, and the parent won't do a save on the second request, so the child can.
	   This works as long as only one process writes to the tmp file.  */

    if (ZFCSG(pid) == 0) {
        ZFCSG(pid) = getpid();
    } else if (ZFCSG(pid) != getpid()) {
        if (ZFCSG(tmp_fp)) {
            (void)fclose(ZFCSG(tmp_fp));
            ZFCSG(tmp_fp) = NULL;
        }
        return;
    }

    SET_TIMER(PREPSAVE);

    if (ndx >= ZFCSG(file_cached_script_alloc)) {
        resize_file_cached_script_vec();
    }

    CHECK(ZFCSG(tmp_fp) || 
          (ZFCSG(tmp_fp) = open_temporary_file(TMP_FILE_PREFIX, &(ZFCSG(tmp_cachename)) TSRMLS_CC)));

    script->dynamic_members.file_cache_index = ndx;
    entry.incache_script_bucket    = bucket;
    entry.record_offset            = ZFCSG(next_file_cache_offset);
	entry.record.uncompressed_size = script->size;
    entry.record.script_offset     = (char *)script - module_addr;
    entry.record.reloc_bvec_size   = zend_accel_script_prepare(script, &rbvec TSRMLS_CC);

    CHECK((entry.record.compressed_size = cache_compress(module_addr, &zbuf, script->size)) > 0);

    SET_TIMER(CACHEWRITE);

    CHECK(fwrite(zbuf, 1, entry.record.compressed_size, ZFCSG(tmp_fp))==entry.record.compressed_size);
    CHECK(fwrite(rbvec, 1,entry.record.reloc_bvec_size, ZFCSG(tmp_fp))==entry.record.reloc_bvec_size);

	/* The tmp file must be flushed after the fwrite because if the PHP script forks between writes,
       then the child will inherit the unflushed content and when it does the fclose this will be 
       written out to the temp file and again by the parent!! */
	(void) fflush(ZFCSG(tmp_fp));

    COLLECT_TIMER(CACHEWRITE);

    DEBUG6(LOAD, "written %*s at %u Size:%u CS:%u RBVS:%u", bucket->key_length, bucket->key, 
                 ZFCSG(next_file_cache_offset), script->size,
                 entry.record.compressed_size, entry.record.reloc_bvec_size);
    ZFCSG(next_file_cache_offset) += entry.record.compressed_size + entry.record.reloc_bvec_size;  
    efree(zbuf); zbuf = NULL;

# if (ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO) && !defined(ZTS)
// TODO: Interned string support
//   if (zbuf_size < compressBound(entry.record.full_interned_size) {
//        zbuf = erealloc(entry.record.full_interned_size);
//    }
//    CHECK((entry.record.compressed_interned_size = cache_compress(module_addr, &zbuf, entry.record.full_interned_size)) > 0);
//    CHECK(fwrite(zbuf, 1, zbuf_length, ZFCSG(tmp_fp))==zbuf_length);
//    ZFCSG(next_file_cache_offset) += entry.record.compressed_interned_size;
//    efree(zbuf); zbuf = NULL:
# endif

    zend_accel_script_relocate(&entry, module_addr, rbvec TSRMLS_CC);  /* undo relocation side-effects */
#ifdef ACCEL_DEBUG
    do {
        zend_uint i;
        IF_DEBUG(RELR) {
            for (i = 0; i < entry.record.uncompressed_size; i += sizeof(char**)) {
                if (*(char**)(module_addr + i) != (*(char**)(ZFCSG(reloc_script_image) + i))) {
                    DEBUG4(RELR,"Reference mismatch at %p (+%08x) to %p vs %p", module_addr + i, i,
                                *(char**)(module_addr + i),*(char**)ZFCSG(reloc_script_image));
                }
            }
        }
    } while (0);
#endif
    efree(rbvec);
    efree(ZFCSG(reloc_bitflag));
    ZFCSG(file_cached_scripts)[ndx] = entry;
    COLLECT_TIMER(PREPSAVE);
    return;

error:
	zend_accel_error(ACCEL_LOG_WARNING, "internal failure during cache write of %s", bucket->key);
    ZFCSG(file_cache_dirty) = 1;
    EFREE(zbuf);
    EFREE(rbvec);
    EFREE(interned_vec);
    cleanup_cache_files();
    COLLECT_TIMER(PREPSAVE);
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
		CHECK(fseek(ZFCSG(in_fp), offset, SEEK_SET)==0);
	}

    buf_len = script->record.compressed_size +
              script->record.reloc_bvec_size;
    buf = emalloc(buf_len);

    SET_TIMER(CACHEREAD);

    CHECK(fread((void *) buf, 1, buf_len, ZFCSG(in_fp)) == buf_len);

    COLLECT_TIMER(CACHEREAD);

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
    zend_accel_script_relocate(script, obuf, reloc_bvec TSRMLS_CC);
    efree(buf);
	zend_shared_alloc_unlock(TSRMLS_C);
    DEBUG6(LOAD, "read %*s from %u Size:%u CS:%u RBVS:%u", bucket->key_length, bucket->key, 
                 offset, script->record.uncompressed_size,
                 script->record.compressed_size, script->record.reloc_bvec_size);
	return;

error:
	zend_accel_error(ACCEL_LOG_WARNING, "internal failure file cache module: %s", 
                                        bucket->key);
    ZFCSG(file_cache_dirty) = 1;
    EFREE(buf);
    EFREE(ZFCSG(file_cached_scripts));
    fclose(ZFCSG(in_fp));
    ZFCSG(in_fp)=NULL;
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
    char *cache_path = NULL, *cache_dir, *base_name, *resolved_path, resolved_dir[MAXPATHLEN];
    pcre *re         = NULL;
    pcre_extra *rex  = NULL;
    const char *error;
    int error_offset, n_pats, path_len, dir_len;
	zend_ulong base_name_len;
    char  tmp_path[MAXPATHLEN];

    /* Only do replacement processing if the cache parameters are set. */ 
    if (!filename || !repl || repl[0] =='\0') { 
        return NULL;
    } 

    if (!filt || filt[0] =='\0') {
		cache_path = repl;
		path_len   = strlen(repl);
	} else {
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
					return NULL;
		        }
 				path_len = q - tmp_path;
				tmp_path[path_len] = 0;
				cache_path = tmp_path;
		    }
		}
		if (re) {
		    pcre_free(re);
		}
		if (rex) {
		    pcre_free(rex);
		}
	}       
	cache_dir = estrdup(cache_path);
	dir_len   = php_dirname(cache_dir, strlen(cache_dir));
	if (!VCWD_REALPATH(cache_dir, resolved_dir)) {
		efree(cache_dir);
		return NULL;
	}
	efree(cache_dir);
    php_basename(cache_path, path_len, NULL, 0, &base_name, &base_name_len TSRMLS_CC);
	resolved_path = emalloc(strlen(resolved_dir) + 1 + base_name_len + 1);
	sprintf(resolved_path, "%s/%s", resolved_dir, base_name);
	efree(base_name);
	return resolved_path;
}

static FILE *open_temporary_file(char* prefix, char **name TSRMLS_DC)
{ENTER(open_temporary_file)
    char *tmp_dir, *tmp_name;
    FILE *tmp_fd;
	int dir_len, tmp_file; 

	tmp_dir = estrdup(ZFCSG(in_cachename));
    dir_len = php_dirname(tmp_dir, strlen(tmp_dir));
	tmp_name = emalloc(dir_len + strlen(prefix) + sizeof("/XXXXXX."));
	sprintf(tmp_name, "%s/%sXXXXXX", tmp_dir, prefix);
	efree(tmp_dir);

	tmp_file = mkstemp(tmp_name);
	if (tmp_file >0 && (tmp_fd = fdopen(tmp_file, "wbx")) != NULL) {
        *name = tmp_name;
        return tmp_fd;
    }         

 	zend_accel_error(ACCEL_LOG_ERROR, "Unable to create temporary file: %s", tmp_name);
    efree(tmp_name);
	return NULL;
}

int cache_compress(const char* source, char** dest, int source_size)
{ENTER(cache_compress)
    int dest_size;
    int algo;
    TSRMLS_FETCH();

    SET_TIMER(DEFLATE);
    algo = ZCG(accel_directives).compression_algo;

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
            COLLECT_TIMER(DEFLATE);
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

    SET_TIMER(INFLATE);

    if (!source || !dest || !source_size || !dest_size) {
        return 0;
    }

    if (ZCG(accel_directives).compression_algo == 1) { /* Standard zlib */
        zend_ulong dest_length = dest_size;

        if (uncompress((unsigned char *)dest, &dest_length, (unsigned char *)source, source_size) == Z_OK &&
            dest_size > 0 && dest_length == (unsigned) dest_size) {
            COLLECT_TIMER(INFLATE);
            return 1;
        }
    } else if (ZCG(accel_directives).compression_algo == 2 ||
               ZCG(accel_directives).compression_algo == 3) { /* LZ4 & LZ4HC compress */
        if (dest_size == LZ4_decompress_safe(source, dest, source_size, dest_size)) {
            COLLECT_TIMER(INFLATE);
            return 1;
        }
    }

    return 0;
}

/* Each byte of reloc_bitflag has 1 bit per pointer in the module (as all pointers are aligned),
   so each byte maps onto 8*SIZEOF_SIZE_T bytes of the module, with the ls pointer mapping onto
   the lsb of the byte.  first_bit is just a quick way of finding the first set bit low-to-high */  
static const zend_uchar first_bit[] = {
    8,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    6,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    7,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    6,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0};
zend_uint zend_accel_prepare_memory(zend_uchar **rbvec TSRMLS_DC)
{ENTER(prepare_memory)
    /* reloc_bitflag is scanned twice: the first time to compute the size of the relocation vector;
       the second to generate the relocation vector and convert the tagged pointers to relocatable
       offset form. */
    zend_uint   n     = ZFCSG(reloc_bitflag_size) * 8;
    zend_uchar *p     = ZFCSG(reloc_bitflag);
    char      **q     = (char **)ZFCSG(module_base); /* treat the module as an array of (char *)s */
    char       *t;
    zend_uchar *reloc_bvec, *r;
    zend_uint  i, delta, last, cnt;

    /* 1st pass over the bit vector to compute size of the corresponding relocation vector */
    for (i = 0, last = 0, cnt = 0; i<n; i+=8) {
        zend_uchar b = *p++;
        while (b) {
            zend_uchar j = first_bit[b];          
            b ^= 1<<j;
            cnt++;
            /* add extra bytes when multi-byte sequences are used */
            for (delta = (i + j) - last; delta>0x7f; delta >>= 7, cnt++) { }
            last = i + j;
        }
    }
    cnt++;
    reloc_bvec = (zend_uchar *) emalloc(cnt);

    /* 2nd pass creates the relocation vector and relocates the pointers to relative format */
    for (i = 0, last = 0, p = ZFCSG(reloc_bitflag), r = reloc_bvec; i<n; i+=8) {
        zend_uchar b = *p++;
        while (b) {
            zend_uchar j = first_bit[b];          
            char     **s = q + (i + j), *sval;
            b ^= 1<<j;

            /* generate byte vector */
            delta = (i + j) - last;
            last  = i + j;
            if (delta <= 0x7f) { /* the typical case */
                *r++ = (zend_uchar) delta;
            } else {             /* handle the multi-byte cases */
               /* Emit multi-bytes lsb first with 7 bits sig; high-bit set to indicate follow-on. */
                while (delta > 0x7f) {
                    *r++ = (zend_uchar) (delta & 0x7f) | 0x80;
                    delta >>= 7;
                }
                *r++ = (zend_uchar) delta;
            }
            /* Now relocate the pointer itself, all tagged pointers should be internal to the 
               module, an interned string or an (already converted) handler */
            sval = *s;
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
            if IS_INTERNED(sval) {
                *s -= (size_t)CG(interned_strings_start) - ZEND_ACCEL_INTERN_FLAG;
                DEBUG3(RELR, "relocating %p interned string %p -> %p", s, sval, *s);
            } else 
#endif
            if (((size_t) sval & FLAG_MASK) == 0 && IS_INTERNAL(sval)) {
                *s -= (size_t)ZFCSG(module_base) - ZEND_ACCEL_INTERNAL_FLAG;
                DEBUG3(RELR, "relocating %p internal %p -> %p", s, sval, *s);

            } else if (((size_t) *s & FLAG_MASK) == ZEND_ACCEL_HASH_FLAG) {
                *s -= (size_t)ZFCSG(module_base);
                DEBUG3(RELR, "relocating %p HashTable->arBuckets %p -> %p", s, sval, *s);

            } else if (((size_t) *s & FLAG_MASK) == ZEND_ACCEL_HANDLER_FLAG) {
                *s -= (size_t)ZFCSG(module_base);
                DEBUG3(RELR, "relocating %p  op_array->opcodes %p -> %p", s, sval, *s);

            } else {
                BREAK_HERE(s);   /* Oops -- something has gone wrong */
            }            
        }
    }
    *r++ = 0;
    assert (r == reloc_bvec + cnt);

#ifdef ACCEL_DEBUG
    for (t = ZFCSG(module_base); t < ZFCSG(module_end); t += sizeof(char **)) {
        if (IS_INTERNAL(*(char **)t)) {
            BREAK_HERE(t);
        }
    }
#endif  
    *rbvec = reloc_bvec;
    return cnt;
}        
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
static const Bucket *uninitialized_bucket = NULL;
#endif

/* To relocate the hastable, the relative form of the pListNext chain is converted to absolute 
   pointer addresses and iterated over to generate the reverse pListlast chain and the pData -> 
   pDataPtr links where needed.  The table is then rehashed to recover the pNext / pLast chains
   and the arBuckets pointers */ 
static void hash_relocate_for_execution(HashTable *ht)
{ENTER(hash_relocate_for_execution)
    DEBUG2(RELR, "relocating HT %p (%u elements) ", ht, ht->nNumOfElements);

	if (ht->nNumOfElements) {
		Bucket *p, *pListLast = NULL;
        RELOCATE_PI(Bucket, ht->pListHead);
        p = ht->pListHead;
		while (1) {
			if (p->pDataPtr) {
			    p->pData = &p->pDataPtr;
			}
			p->pListLast = pListLast;
			pListLast = p;
			if (!p->pListNext) {
				break;
			}
			RELOCATE_PI(Bucket, p->pListNext);
			p = p->pListNext;						
		}
		ht->pListTail = p;
		(void) zend_hash_rehash(ht);
        RELOCATE_PI_NZ(Bucket,ht->pInternalPointer);
    } 
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
	else if (ht->nTableMask==0) {
		ht->arBuckets = (Bucket **) &uninitialized_bucket;  /* override ptr to  (PHP >= 5.4) */
	} 
#endif
}

static void set_op_array_handlers_for_execution(zend_op_array *op_array)
{ENTER(set_op_array_handlers_for_execution)
    uint i;
    for (i = 0; i<op_array->last; i++) {
        if (!op_array->opcodes[i].handler) {
            ZEND_VM_SET_OPCODE_HANDLER(op_array->opcodes + i);
        }
    }
}  

/* The relocation byte vector (rbvec) contains the byte offset (in size_t units) of each * pointer
   in the SMA to be relocated. As these pointers are a lot denser than every * 127 longs (1016
   bytes), the encoding uses a simple high-bit multi-byte escape to * encode exceptions. Also note
   that 0 is used as a terminator excepting that the first * entry can validly be '0'. */
void zend_accel_script_relocate(zend_file_cached_script *entry, char *memory_area, char *rbvec TSRMLS_DC)
{ENTER(zend_accel_script_relocate)
    zend_persistent_script *script = (zend_persistent_script *) entry->incache_script_bucket->data;
    size_t        *q               = (size_t *) memory_area;
    unsigned char *p               = (unsigned char *) rbvec;

    ZFCSG(module_base) = memory_area;
   /* Use a do {} while loop because the first byte offset can by zero; any other is a terminator */
    do {
        char *old_qv, *linked_rec;
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

        old_qv = *(char **)q;
        switch (*q & FLAG_MASK) {
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
            case ZEND_ACCEL_INTERN_FLAG:
                *q += (size_t)(ZCSG(interned_strings_start) - ZEND_ACCEL_INTERN_FLAG);
                DEBUG3(RELR, "relocating %p interned string %p -> %p", q, old_qv, *(char **)q);
                break;
#endif
            case ZEND_ACCEL_INTERNAL_FLAG:
                *q += (size_t)(memory_area - ZEND_ACCEL_INTERNAL_FLAG);
                DEBUG3(RELR, "relocating %p internal %p -> %p", q, old_qv, *(char **)q);
                break;

            case ZEND_ACCEL_HASH_FLAG:
                /* The HT->arBuckets field is tagged */
                *q += (size_t)memory_area - ZEND_ACCEL_HASH_FLAG;
                linked_rec = (char *)q - (size_t)&(((HashTable *) 0)->arBuckets);
                DEBUG4(RELR, "relocating %p internal %p -> %p. Now relocating HT at %p", q, old_qv, *(char **)q, linked_rec);
                hash_relocate_for_execution((HashTable *)linked_rec);
                break;

            case ZEND_ACCEL_HANDLER_FLAG:
                /* The op_array->opcodes field is tagged */
                *q += (size_t)memory_area - ZEND_ACCEL_HANDLER_FLAG;
                linked_rec = (char *)q - (size_t)&(((zend_op_array *) 0)->opcodes);
                DEBUG4(RELR, "relocating %p internal %p -> %p. Now relocating handlers for op_array at %p", q, old_qv, *(char **)q, linked_rec);
                set_op_array_handlers_for_execution((zend_op_array *)linked_rec);
                break;

            default:
                BREAK_HERE(q);
        }

    } while (*p != '\0');
   
    assert((char *)q < memory_area + script->size);
}

#endif /* OPCACHE_ENABLE_FILE_CACHE */

