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

#ifndef ZEND_ACCELERATOR_DEBUG_H
#define ZEND_ACCELERATOR_DEBUG_H

#define ACCEL_LOG_FATAL					0
#define ACCEL_LOG_ERROR					1
#define ACCEL_LOG_WARNING				2
#define ACCEL_LOG_INFO					3
#define ACCEL_LOG_DEBUG					4

void zend_accel_error(int type, const char *format, ...);

#define PERSISTENT 1

#ifdef __DEBUG_ACCEL__
# define ACCEL_DEBUG 1
#endif

# define ACCEL_DBG_ALLOC  (1<<0) /* Storage Allocation */
# define ACCEL_DBG_KEY    (1<<1)  /* Key resolution */
# define ACCEL_DBG_HASH   (1<<2)  /* Hash Functions */
# define ACCEL_DBG_RELR   (1<<3)  /* Missed relocation report */
# define ACCEL_DBG_LOAD   (1<<4)  /* Load/Unload Info */
# define ACCEL_DBG_ENTER  (1<<5)  /* Print out function entry audit */
# define ACCEL_DBG_COUNTS (1<<6)  /* Print out function summary counts */
# define ACCEL_DBG_INDEX  (1<<7)  /* Print out cache index save and load */
# define ACCEL_DBG_INTN   (1<<8)  /* Duplicate intern allocation */
# define ACCEL_DBG_ZVAL   (1<<9)  /* ZVAL tracking */
# define ACCEL_DBG_LOG_OPCODES (1<<10)  /* Opcode loggin */

#ifdef ACCEL_DEBUG
extern int accel_directives_debug_flags, accel_directives_debug_audit;
#define ENTER(s) int dummy_to_be_ignored = accel_directives_debug_audit ? accel_debug_enter(#s) : 0;
extern int ACCEL_debug_enter(char *s); 
#define IF_DEBUG(flg) if (accel_directives_debug_flags & ACCEL_DBG_ ## flg)
#define DEBUG0(flg,fmt) IF_DEBUG(flg) zend_accel_error(ACCEL_LOG_DEBUG,fmt)
#define DEBUG1(flg,fmt,a1) IF_DEBUG(flg) zend_accel_error(ACCEL_LOG_DEBUG,fmt, a1)
#define DEBUG2(flg,fmt,a1,a2) IF_DEBUG(flg) zend_accel_error(ACCEL_LOG_DEBUG,fmt,a1,a2)
#define DEBUG3(flg,fmt,a1,a2,a3) IF_DEBUG(flg) zend_accel_error(ACCEL_LOG_DEBUG,fmt,a1,a2,a3)
#define DEBUG4(flg,fmt,a1,a2,a3,a4) IF_DEBUG(flg) zend_accel_error(ACCEL_LOG_DEBUG,fmt,a1,a2,a3,a4)
#define DEBUG5(flg,fmt,a1,a2,a3,a4,a5) IF_DEBUG(flg) zend_accel_error(ACCEL_LOG_DEBUG,fmt,a1,a2,a3,a4,a5)
#else
# define ENTER(s) 
#define IF_DEBUG(flg) if (0)
#define DEBUG0(flg,fmt)
#define DEBUG1(flg,fmt,a1)
#define DEBUG2(flg,fmt,a1,a2)
#define DEBUG3(flg,fmt,a1,a2,a3)
#define DEBUG4(flg,fmt,a1,a2,a3,a4)
#define DEBUG5(flg,fmt,a1,a2,a3,a4,a5)
#endif
#define NOENTER(s)

void accel_debug_dump(zend_op_array *array);
int accel_debug_enter(char *s);

#endif /* _ZEND_ACCELERATOR_DEBUG_H */
