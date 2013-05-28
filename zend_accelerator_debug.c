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
   | Authors: Andi Gutmans <andi@zend.com>                                |
   |          Zeev Suraski <zeev@zend.com>                                |
   |          Stanislav Malyshev <stas@zend.com>                          |
   |          Dmitry Stogov <dmitry@zend.com>                             |
   +----------------------------------------------------------------------+
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#ifdef ZEND_WIN32
# include <process.h>
#endif
#include "ZendAccelerator.h"

void zend_accel_error(int type, const char *format, ...)
{NOENTER(zend_accel_error)
    va_list args;
	time_t timestamp;
	char *time_string;
	FILE * fLog = NULL;
	TSRMLS_FETCH();

	if (type > ZCG(accel_directives).log_verbosity_level) {
		return;
	}

	timestamp = time(NULL);
	time_string = asctime(localtime(&timestamp));
	time_string[24] = 0;

	if (!ZCG(accel_directives).error_log ||
	    !*ZCG(accel_directives).error_log ||
	    strcmp(ZCG(accel_directives).error_log, "stderr") == 0) {

		fLog = stderr;
	} else {
		fLog = fopen(ZCG(accel_directives).error_log, "a+");
		if (!fLog) {
			fLog = stderr;
		}
	}

#ifdef ZTS
    fprintf(fLog, "%s (%lu): ", time_string, (unsigned long)tsrm_thread_id());
#else
    fprintf(fLog, "%s (%d): ", time_string, getpid());
#endif

	switch (type) {
		case ACCEL_LOG_FATAL:
			fprintf(fLog, "Fatal Error ");
			break;
		case ACCEL_LOG_ERROR:
			fprintf(fLog, "Error ");
			break;
		case ACCEL_LOG_WARNING:
			fprintf(fLog, "Warning ");
			break;
		case ACCEL_LOG_INFO:
			fprintf(fLog, "Message ");
			break;
		case ACCEL_LOG_DEBUG:
			fprintf(fLog, "Debug ");
			break;
	}

    va_start(args, format);
    vfprintf(fLog, format, args);
    va_end(args);
	fprintf(fLog, "\n");
	switch (type) {
		case ACCEL_LOG_ERROR:
			zend_bailout();
			break;
		case ACCEL_LOG_FATAL:
			exit(-2);
			break;
	}
	fflush(fLog);
	if (fLog != stderr) {
		fclose(fLog);
	}
}

void *accel_resolve_symbol(const char *symbol)
{
    void *addr = NULL;
    DL_HANDLE handle = NULL;
#ifdef PHP_WIN32
    if ((handle = GetModuleHandle(NULL))==NULL) {
        TSRMLS_FETCH();
        zend_accel_error(ACCEL_LOG_WARNING,"unable to fetch current module handle.");
    } else {
        addr = DL_FETCH_SYMBOL(handle, symbol);
        DL_UNLOAD(handle);
    }
#else
    addr = DL_FETCH_SYMBOL(handle, symbol);
#endif

    return addr;
}
#ifdef ACCEL_DEBUG
int accel_directives_debug_flags = 0;
int accel_directives_debug_audit = 0;
void dump(zend_op_array *op_array)
{
	TSRMLS_FETCH();
    void (*dump_op_array) (zend_op_array * TSRMLS_DC) = 
        accel_resolve_symbol("vld_dump_oparray");
    if (dump_op_array) {
        dump_op_array(op_array TSRMLS_CC);
    } else {
        zend_accel_error(ACCEL_LOG_INFO, "vld is not installed or something even worse.");
    }
}
/*  HEALTH WARNING: this code is NOT thread safe as it's only intended for coverage collection
    during development. To keep the code simple, this uses a simple hash + linear scan algo since we
    can't initialize and use a standard PHP HashTable before GINIT. At ~25% table occupancy, there
    are ~1.14 compares per lookup (avg), so it's faster and uses less memory than a HashTable for
    this use.  

    Also the get_stack_depth function is unashamedly x86 -- it's not here to stay; only to help me
    do dynamic analysis of the O+ code base to be refactored. 
*/
#define FUNC_MAX  0x200
#define FUNC_MASK 0x1ff

static int get_stack_depth(void) {
#if defined(__GNUC__)
# if SIZEOF_SIZE_T==8
    register void *fp asm("rbp");
# else
    register void *fp asm("ebp");
# endif
    void *bp = fp;
    int stack_depth = -1;
    while(bp) {
        bp = *(void **)bp;
        stack_depth++; 
    }
    return stack_depth;
#else
    return 1;
#endif
}

static int func_compare(const void *a, const void *b)
{
    return strcmp(*(const char **)a, *(const char **)b);
}

#define FIND(str,n,found) \
    do {found = 2;\
        ulong hash = zend_inline_hash_func(str, strlen(str)); \
        for (n = 0; n < FUNC_MAX; n++) { \
            uint hash_n = ( hash + n ) & FUNC_MASK; \
            n_func_probe++; \
            if (func_table[hash_n].func_name == NULL) \
                { found = 0; n=hash_n; break; } \
            if (strcmp(str, func_table[hash_n].func_name) == 0 ) \
                { found = 1; n=hash_n; break; } \
        } \
        assert(found<2); \
    } while (0)

int accel_debug_enter(char *s)
{
    struct _func_table {
        const char* func_name;
        ulong func_cnt;
    };
    static struct _func_table func_table[FUNC_MAX] = {0};
    static int n_func_probe = 0;
    uint stack_depth,i,ndx,found;
    const char fill[] = "                                                                                                    ";

    FIND(s,ndx,found);
    if (found==0) {
        func_table[ndx].func_name=s;
    }
    func_table[ndx].func_cnt++;
    IF_DEBUG(ENTER) {
        stack_depth = get_stack_depth();
        zend_accel_error(ACCEL_LOG_DEBUG,"Entering %s %s",
                  (stack_depth >= sizeof(fill) ? "" : fill + (sizeof(fill)-stack_depth)),
                  s);
    }
    if (strcmp(s, "accel_shutdown")==0) {
        IF_DEBUG(COUNTS) {
            uint j=0;    
            for (i = 0; i<FUNC_MAX; i++) {
                if (func_table[i].func_name != NULL) {
                    func_table[j++]=func_table[i];
                }
            }
            qsort(func_table, j, sizeof(struct _func_table), func_compare);
            for (i = 0; i<j; i++) {
                zend_accel_error(ACCEL_LOG_DEBUG,"%6i %s",
                                 func_table[i].func_cnt, func_table[i].func_name);
            }
        }
    }
    return 0;
}
#endif

#if 0
    struct timeval s,e; // tv_sec & tv_usec
     (void) clock_gettime(CLOCK_REALTIME, &s); -- needs -lrt option
    struct timespec s,e; // tv_sec & tv_nsec
    (void) gettimeofday(&s, NULL);
#endif
