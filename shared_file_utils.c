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
   |          Andi Gutmans <andi@zend.com>                                |
   |          Zeev Suraski <zeev@zend.com>                                |
   |          Stanislav Malyshev <stas@zend.com>                          |
   |          Dmitry Stogov <dmitry@zend.com>                             |
   +----------------------------------------------------------------------+
*/

#include "zend_shared_alloc.h"
#ifdef OPTIMIZER_PLUS_CLI_PERSISTANCE

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/mman.h>
#include <pcre.h>
#include <zlib.h>
#include "SAPI.h"

/* Notes:

   1) Even thought the will only ever by one thread for CLI and GCI processes, CLI persistance is
      still TSRM enabled to allow CLI based testing of TSRM builds.

   2) TODO: add compile-time checks only to enable OPTIMIZER_PLUS_CLI_PERSISTANCE when PCRE is available.

   3) TODO: GCC on ZCG(cache_path)

   4) TODO: zend_accel_save_sma() runs as part of image rundown by which time a lot of PHP services 
            have run down.  might be worth bumping its hook back to request shutdown to make life 
            simpler.
*/
#define CHUNK 16384
#define FINGERPRINT "CLI ZO++"
#define TMP_FILE_PREFIX "/.ZendO.tmp"
#define CHECK(p) if(!(p)) goto error

typedef struct _saved_sma_header {
    char fingerprint[8];
    uint used;
    uint compressed_size;
    uint rbvec_size;
} saved_sma_header;

static int   load_sma_from_file(FILE *src, uint compressed_size, void *dest, uint *size, 
                                void *buffer, uint buflen);
static int   save_sma_to_file(FILE *dst, uint *compressed_size, void *src, uint size, 
                                void *buffer, uint buflen);
static char *generate_cache_name(TSRMLS_D);
static uint  make_sma_rbvec(zend_shared_segment *shared_segment, unsigned char **rbvec TSRMLS_DC);
static void  relocate_sma(zend_shared_segment *shared_segment, unsigned char *rbvec TSRMLS_DC);

int zend_accel_load_sma(zend_shared_segment *shared_segment)
{ENTER(zend_accel_load_sma)
    size_t size = shared_segment->size;
    void  *addr = shared_segment->p;
    char  *cache_path;
    char  *resolved_path = NULL;
    FILE  *fp;
    saved_sma_header header;
    char  *buffer;
    int    buflen, rc;
	TSRMLS_FETCH();

    if ((cache_path = generate_cache_name(TSRMLS_C)) == NULL) {
        /* no cache file so fail through to normal allocation success */
        DEBUG0(LOAD,"LOAD: no cache file specified");
        return ALLOC_SUCCESS;
    }

/*  ZCG(cache_path) = zend_resolve_path(cache_path, strlen(cache_path) TSRMLS_CC);
    free(cache_path); */
    ZCG(cache_path) = cache_path;

    if (!ZCG(cache_path) && ZCG(cache_path)[0] != '/' ||
        (fp = fopen(cache_path, "rb")) == NULL) {
        /* cache isn't a valid file or we can't open it so again fail through */
        DEBUG1(LOAD,"LOAD: Cache file %s does not exist", cache_path);
        return ALLOC_SUCCESS;
    }

    CHECK(fread((void *) &header, 1, sizeof(header), fp) == sizeof(header) &&
          !memcmp(header.fingerprint, FINGERPRINT, sizeof(header.fingerprint)));

    buflen = size - header.used;
    if (buflen < CHUNK) {
        CHECK(buffer = malloc(CHUNK));
        CHECK(load_sma_from_file(fp, header.compressed_size, addr, &header.used, buffer, CHUNK));
        free(buffer);
    } else {
        buffer = ((char *)addr) + header.used;
        CHECK(load_sma_from_file(fp, header.compressed_size, addr, &header.used, buffer, buflen));
    }

    buffer = (buflen < header.rbvec_size) ? malloc(header.rbvec_size) :
                                            ((char *)addr) + header.used;
    CHECK(buffer && header.rbvec_size == fread(buffer, 1, header.rbvec_size, fp));
    shared_segment->pos = header.used;
    relocate_sma(shared_segment, buffer TSRMLS_CC);
    if (buflen < header.rbvec_size) {
        free(buffer);
    }

    fclose(fp);
    DEBUG3(LOAD,"LOAD: Cache file %s restored to %p (%u bytes)", cache_path, addr, header.used);
    return SUCCESSFULLY_REATTACHED;

error:
	zend_accel_error(ACCEL_LOG_ERROR, "internal failure during SMA load");
    return ALLOC_SUCCESS;
}

void zend_accel_clear_saved_sma(void)
{ENTER(zend_accel_clear_saved_sma)
	TSRMLS_FETCH();
    if (ZCG(cache_path) && ZCG(cache_path)[0] == '/') {
        (void) unlink(ZCG(cache_path));
    }
}

int zend_accel_save_sma(zend_shared_segment *shared_segment)
{ENTER(zend_accel_save_sma)
    size_t size = shared_segment->size;
    void  *addr = shared_segment->p;
    size_t used = shared_segment->pos;
    saved_sma_header header;
    char  *tmp_filename, *buffer;
    zend_shared_segment tmp_shared_segment = *shared_segment;
    unsigned char* rbvec;
    int    fd;
    FILE  *fp;
    int    buflen, rc = FAILURE;
	TSRMLS_FETCH();

    if (!ZCG(cache_path) || ZCG(cache_path)[0] != '/') {
        return FAILURE;
    } 
        
    tmp_filename = malloc(strlen(ZCG(cache_path)) + sizeof(TMP_FILE_PREFIX) + 3 + 8 + 6);
    strcpy(tmp_filename, ZCG(cache_path));
    tmp_filename = dirname(tmp_filename);

    memcpy(header.fingerprint, FINGERPRINT, sizeof(header.fingerprint));
    header.used            = used;
    header.compressed_size = 0;
   
    sprintf(tmp_filename+strlen(tmp_filename), "%s.%08u.XXXXXX", TMP_FILE_PREFIX, getpid());

    if (strlen(tmp_filename) > MAXPATHLEN ||
        (fd = mkstemp(tmp_filename)) == -1 ||
        (fp = fdopen(fd, "wbx")) == NULL) {
        free(tmp_filename);
        return FAILURE;
    } 

    CHECK(fwrite(&header, 1, sizeof(header), fp) == sizeof(header)); 
    CHECK(header.rbvec_size = make_sma_rbvec(shared_segment, &rbvec TSRMLS_CC));

    if (header.rbvec_size) {
        buflen = size - used;
        if (buflen < CHUNK) {
            buffer = malloc(CHUNK);
            rc = save_sma_to_file(fp, &header.compressed_size, addr, used, buffer, CHUNK);
            free(buffer);
        } else {
            buffer = ((char *)addr) + used;
            rc = save_sma_to_file(fp, &header.compressed_size, addr, used, buffer, buflen);
        }
    }

	if (rc == SUCCESS) {
        /* make_sma_rbvec() also converts the SMA to PIC format for saving, however the exit code
           expects it in absolute form (actual only up to and including ZSMMG(shared_segments)[0])
           so relocate it back */
        relocate_sma(&tmp_shared_segment, rbvec TSRMLS_CC);
        CHECK(fwrite(rbvec, 1, header.rbvec_size, fp) == header.rbvec_size);
        free(rbvec);
        rewind(fp);
        CHECK(fwrite(&header, 1, sizeof(header), fp) == sizeof(header));
        (void) fclose(fp);
        (void) close(fd);
		rename(tmp_filename, ZCG(cache_path));
        DEBUG5(LOAD,"LOAD: Cache file %s created from %p (%u bytes compressed to %u, "
                    "%u byte relocation vector)", ZCG(cache_path), addr,
                    header.used, header.compressed_size, header.rbvec_size);        
	} else {
        (void) fclose(fp);
        (void) close(fd);
		(void) unlink(tmp_filename);
	}
    free(tmp_filename);
    return rc;

error:
	zend_accel_error(ACCEL_LOG_ERROR, "internal failure during SMA save");
}

static int load_sma_from_file(FILE *src, uint comp_size, void *dest, uint *size, 
                              void *buffer, uint buflen)
{ENTER(load_sma_from_file)
    int ret;
    z_stream zs = {0};

    if ((ret = inflateInit(&zs)) != Z_OK) {
        return ALLOC_SUCCESS;
    }

    zs.next_out  = dest;
    zs.avail_out = *size;
    do {
        zs.next_in  = buffer;
        zs.avail_in = fread(buffer, 1, 
                            ((comp_size-zs.total_in) < buflen ? comp_size-zs.total_in : buflen), 
                            src);
        if (ferror(src) || zs.avail_in == 0 || (ret = inflate(&zs, Z_NO_FLUSH)) < 0) {
            break;
        }

    } while (ret != Z_STREAM_END);

    (void)inflateEnd(&zs);    
    if (ret < 0) {
        memset(dest, 0, *size);
        *size = 0;
        return ALLOC_SUCCESS;
    }

	smm_shared_globals = (zend_smm_shared_globals *) (((char *) dest) + sizeof(zend_shared_memory_block_header));
    return SUCCESSFULLY_REATTACHED;
}

static int save_sma_to_file(FILE *dst, uint *compressed_size, void *src, uint size, void *buffer, uint buflen)
{ENTER(save_sma_to_file)
    int flush, ret;
    uint processed, have;
    z_stream zs = {0};

    if ((ret = deflateInit(&zs, 6)) != Z_OK) {
        return ret;
    }
    zs.next_in  = src;
    zs.avail_in = size;
    do {
        zs.next_out  = buffer;
        zs.avail_out = buflen;
        ret = deflate(&zs, Z_FINISH);
        assert(ret != Z_STREAM_ERROR);
        processed = buflen - zs.avail_out;
        if (fwrite(buffer, 1, processed, dst) != processed || ferror(dst)) {
            (void)deflateEnd(&zs);
            return FAILURE;
        }
    } while (zs.avail_out == 0);
    assert(ret == Z_STREAM_END); 
    /* clean up and return */
    *compressed_size = zs.total_out;
    (void)deflateEnd(&zs);
    
    return SUCCESS;
}

/* generate_cache_name() is called as part of the accelerator startup processing that is deferred
   to accelerator activation if CLI persistance is configured. Because this has been deferred to
   activation, the SAPI context is available to decode the requested filename. Native PCRE is used
   here, as the PHP PCRE functions require components of the Zend execution environment which are
   not initialised at this point. */ 
static char *generate_cache_name(TSRMLS_D)
{ENTER(generate_cache_name)

    char *filt       = ZCG(accel_directives).cache_pattern;
    char *repl       = ZCG(accel_directives).cache_replacement;
    char *filename   = SG(request_info).path_translated;
    char *cache_path = NULL;
    pcre *re         = NULL;
    pcre_extra *rex  = NULL;
    const char *error;
    int error_offset, n_pats; 

    /* Only do replacement processing if the cache parameters are set. */ 
    if (!filt || filt[0] =='\0' || !repl || repl[0] =='\0') { 
        return NULL;
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
                         "Cache pattern failed to match; Caching is suppressed.");
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

/* {{{ make_sma_rbvec 
   BOTCH WARNING: This code is a pull from LPC, but restyled in the ZendOptimizer (zero inline
   documentation) coding style. The LPC version used intelligent taging to identify valid pointers
   for relocation. This version simply identifies any size_t value in the address range of the SMA
   as an SMA- internal pointer. This works for now on 64bit architectures as the SMA addr is a pretty
   high 64bit value (eg. 0x00007f90cbdf3000) which won't be in the SMA unless it is an internal
   pointer. This will need to be fixed in the longer term, but my preference would be to addr the
   rbvec on a per module basis so that individual modules could be relocated on demand. */
static uint make_sma_rbvec(zend_shared_segment *shared_segment, unsigned char **rbvec TSRMLS_DC)
{ENTER(make_sma_rbvec)
    size_t size = shared_segment->size;
    void  *addr = shared_segment->p;
    size_t used = shared_segment->pos;
    void **p, **lastp, **pend;
    unsigned char *reloc_bvec, *q;
    uint   delta, cnt = 1;

    /* 1st pass to compute size of the relocation vector */
    for (p = (void **)addr, lastp = p, pend = p + (used / sizeof(void*)); p < pend; p++) {
        if (!*p) continue;
        if ( ((size_t)((char *)*p - (char *)addr)) < used ) {
            cnt++;
            /* add extra bytes when multi-byte sequences are used */
            for (delta=(uint)(p-lastp); delta>=0x80; delta >>= 7, cnt++) { }
            lastp = p;
        }
    }

	reloc_bvec = (unsigned char *) malloc(cnt);
	if (!reloc_bvec) {
		zend_accel_error(ACCEL_LOG_ERROR, "malloc() failed");
		return 0;
	}

    /* 2nd pass to generate the relocation byte vector */
    for (p = (void **)addr, q = reloc_bvec, lastp = p, pend = p + (used / sizeof(void*)); 
         p < pend; p++) {
        if ( ((size_t)((char *)*p - (char *)addr)) < used ) {
            delta = (uint)(size_t)(p-lastp);
            *p = (void *) (*(char **)p - (char *)addr); /* convert ptr to offset */
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
    }
    *q++ = '\0'; /* add an end marker so the reverse process can terminate */
    assert((zend_uchar *)q == reloc_bvec+cnt);
    *rbvec = reloc_bvec;
    return cnt;
}
/* }}} */

/* {{{ relocate_sma. The relocation byte vector (rbvec) contains the byte offset (in size_t units)
       of each * pointer in the SMA to be relocated. As these pointers are a lot denser than every *
       127 longs (1016 bytes), the encoding uses a simple high-bit multi-byte escape to * encode
       exceptions. Also note that 0 is used as a terminator excepting that the first * entry can
       validly be '0'. */
static void relocate_sma(zend_shared_segment *shared_segment, unsigned char *rbvec TSRMLS_DC)
{ENTER(relocate_sma)
    size_t         size        = shared_segment->size;
    size_t         addr_offset = (size_t) shared_segment->p;
    size_t        *q           = (size_t *) shared_segment->p;
    size_t         max_qval    = shared_segment->pos;
    unsigned char *p           = rbvec;

   /* Use a do {} while loop because the first byte offset can by zero; any other is a terminator */
    do {
        if (p[0]<128) {         /* offset <1K the typical case */
            q += *p++;
        } else if (p[1]<128) {  /* offset <128Kb */
            q += (uint)(p[0] & 0x7f) + (((uint)p[1])<<7);
            p += 2;
        } else if (p[2]<128) {  /* offset <16Mb */
            q += (uint)(p[0] & 0x7f) + ((uint)(p[1] & 0x7f)<<7) + (((uint)p[2])<<14);
            p += 3;
        } else if (p[3]<128) {  /* offset <2Gb Ho-ho */
            q += (uint)(p[0] & 0x7f)      + ((uint)(p[1] & 0x7f)<<7) + 
                ((uint)(p[2] & 0x7f)<<14) + (((uint)p[3])<<21);
            p += 4;
        }
        if (*q >= max_qval) {
            zend_accel_error(ACCEL_LOG_ERROR, 
                             "Relocation error: invalid offset %p at offset %08lx in SMA", 
                             *((void **)q), (char *)q - (char *)addr_offset);
        } else { 
            *q += addr_offset;
        }
    } while (*p != '\0');
   
    assert((char *)q < (char *)shared_segment->p + max_qval);
}
/* }}} */

#endif /* OPTIMIZER_PLUS_CLI_PERSISTANCE */
