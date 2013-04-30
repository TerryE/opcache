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

#include "zend_shared_alloc.h"
#include "main/SAPI.h"

#ifdef OPCACHE_ENABLE_FILE_CACHE
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#if defined(MAP_ANON) && !defined(MAP_ANONYMOUS)
# define MAP_ANONYMOUS MAP_ANON
#endif

#ifndef MIN
# define MIN(x, y) ((x) > (y)? (y) : (x))
# define MAX(x, y) ((x) > (y)? (x) : (y))
#endif

#define SEG_ALLOC_SIZE (8*1024*1024)
/* The malloc allocator uses a lazy allocation strategy to allocate its segments.  create_segments()
   may be called multiple times.  The first time it acts much as the other allocators, but only 
   mallocing one segment of at most SEG_ALLOC_SIZE.  On each subsequent call (segments_p==NULL)
   it will malloc and add an additional segment. */
static int create_segments(size_t size, zend_shared_segment ***segments_p, int *segments_count_or_ndx, char **error_in)
{ENTER(create_segments-malloc)
    size_t segments_allocation, segment_size, block_size;
	zend_shared_segment *segment, **segments_vec;
    int segments_count;

    if (ZSMMG(use_file_cache)==0) {
        size_t requested_size    = size;
        int segments_count, i;

        if (strcmp(sapi_module.name, "cli") != 0 && strcmp(sapi_module.name, "cgi-fcgi") != 0) {
            return ALLOC_FAILURE;
        }

        segments_count = (requested_size+SEG_ALLOC_SIZE-1) / SEG_ALLOC_SIZE;
        segments_vec = (zend_shared_segment **) calloc(segments_count, sizeof(zend_shared_segment) + sizeof(void *));
        if (!segments_vec) {
	        *error_in = "calloc";
	        return ALLOC_FAILURE;
        }

        segment = (zend_shared_segment *) (segments_vec + segments_count);
        for (i = 0; i<segments_count; i++) {
            segments_vec[i] = segment + i;
        }

        segment_size = MIN(requested_size, SEG_ALLOC_SIZE);
        if ((segment[0].p = malloc(segment_size)) == NULL) {
	        *error_in = "malloc";
	        return ALLOC_FAILURE;
        }
        segment[0].size = segment_size;

        if (requested_size > segment_size) {
	        segment[1].size = requested_size - segment_size;
        }

        *segments_p = segments_vec;
        *segments_count_or_ndx = segments_count;        
    } else { /* ZSMMG(use_file_cache) == 1 */
        size_t minimum_size = size;
        size_t remaining;
        int next_ndx = *segments_count_or_ndx;

        segment = ZSMMG(shared_segments)[0];
        remaining = segment[next_ndx].size;
        segment_size = MAX(minimum_size, MIN(SEG_ALLOC_SIZE, remaining));

        if ((segment[next_ndx].p = malloc(segment_size)) == NULL) {
            /* no explicit error handling needed as this will trigger the nec error in calling rtn */
            segment[next_ndx].size = 0;
	        return ALLOC_FAILURE;
        }
        segment[next_ndx].size = segment_size;
        if (remaining > segment_size) {
	        segment[next_ndx + 1].size = remaining - segment_size;
        }
    }
    return ALLOC_SUCCESS;
}

static int detach_segment(zend_shared_segment *shared_segment)
{ENTER(detach_segment-malloc)
    if (shared_segment->p) {
	    free(shared_segment->p);
        shared_segment->p = NULL;
        }
	return 0;
}

static size_t segment_type_size(void)
{ENTER(segment_type_size-malloc)
	return sizeof(zend_shared_segment);
}

zend_shared_memory_handlers zend_alloc_malloc_handlers = {
	create_segments,
	detach_segment,
	segment_type_size
};

#endif /* OPCACHE_ENABLE_FILE_CACHE */
