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
   |          Terry Ellison<terry@ellisons.org.uk>                        |
   +----------------------------------------------------------------------+
*/

#include "zend.h"
#include "ZendAccelerator.h"
#include "zend_extensions.h"
#include "zend_shared_alloc.h"
#include "zend_vm.h"
#include "zend_constants.h"
#include "zend_operators.h"
#include "zend_accelerator_util_funcs.h"
/*
 Overview of Position Independent (PI) and Absolute (ABS) Address processing of the compiled script
 structure hierarchy.
  *  This must be converted from ABS -> PI format for saving to the file cache. All related
     functions include "prepare" in their name.
  *  This must be reconverted back from PI -> ABS on reload from the file cache into SMA (typically
     at a different location to the initial compile). All related functions include "relocate" in
     their name.
  *  PI->ABS is done once-per-request, but ABS->PI is only done once-per-compile, so where practical  
     processing is hoisted from the relocate to prepare functions to streamline the former.
  *  All data elements and internal table structures are allocated within in a single brick (based
     at script->mem and script->size long), hence relative addressing within the brick is PI.
  *  For PHP >5.3 when string interning is used, the offset into the string intern pool is also PI.
  *  All Zend compiler generated pointers and pointer targets are size_t aligned.  Prepare
     processing can therefore use the bottom bits for PI addresses to tag the address type.
  *  The general logic flow of the prepare processing largely mirrors (and was derived from) that of
     the zend_persist.c module.
 */

#if SIZEOF_SIZE_T == 8
#  define RBF_SHIFT 6
#elif SIZEOF_SIZE_T == 4
#  define RBF_SHIFT 5
#else
#  error "Unknown size_t length.  Only 4 or 8 supported"
#endif

#define FLAG_MASK       (SIZEOF_SIZE_T-1)
#define RBF_MASK        0x07
#define BYTES_PER_RELOC_MASK_BYTE (SIZEOF_SIZE_T * 8)
#define ALIGNED_PTR_MASK ~(size_t)(SIZEOF_SIZE_T-1)

#define TAG(p) set_tag((char **)(&p) LINECC)
#define IS_TAGGED(p) (p && is_tag((char **)(&p) LINECC))
#define IS_INTERNAL(s) (((s) >= ZFCSG(module_base)) && ((s) < ZFCSG(module_end)))
#define MAKE_PI(p) make_pi((char **)(&p) LINECC)
#define TAG_TYPE(tag,p) set_tagged_type(ZEND_ACCEL_ ## tag ## _FLAG, (char **)&p); TAG(p)
#define TAG_NZ(p) if (p) {TAG(p);}
#define MAKE_PI_NZ(p) if (p) {MAKE_PI(p);}

#define TAG_ZVAL(zv) tag_zval_p(&zv TSRMLS_CC)
#define TAG_ZVAL_P(zvp) tag_zval_p(zvp TSRMLS_CC); TAG(zvp); 
#define TAG_ZVAL_PP(zvpp) tag_zval_pp(zvpp TSRMLS_CC)
#define HASH_PREPARE(ht, func) hash_prepare(&ht, (zend_prepare_func_t)func TSRMLS_CC)
#define HASH_PREPARE_P(htp, func) hash_prepare(htp, (zend_prepare_func_t)func TSRMLS_CC); TAG(htp)

#define HASH_TAG_ZVAL_PTR(ht) HASH_PREPARE(ht, tag_zval_pp)
#define HASH_PREPARE_P_ZVAL_PTR(htp) HASH_PREPARE_P(htp, tag_zval_pp)

#ifdef ACCEL_DEBUG
#  define LINECC ,__LINE__ 
#  define LINEDC ,uint line 
#else
#  define LINECC
#  define LINEDC
#endif

static void set_tag(char **p LINEDC) 
{ENTER(set_tag)
    size_t     byte_offset = (char*) p - ZFCSG(module_base);
    uint       mask_offset = byte_offset>>RBF_SHIFT;
    zend_uchar bitmask     = 1 << ((byte_offset/sizeof(char **)) & RBF_MASK);

    DEBUG3(RELR, "tagging %p -> %p at line %u", p, *p, line);
    ZFCSG(reloc_bitflag)[mask_offset] |= bitmask;
}

static int is_tag(char **p LINEDC) 
{ENTER(is_tag)
    size_t     byte_offset = (char*) p - ZFCSG(module_base);
    uint       mask_offset = byte_offset>>RBF_SHIFT;
    zend_uchar bitmask     = 1 << ((byte_offset/sizeof(char **)) & RBF_MASK);
    int        result      = (ZFCSG(reloc_bitflag)[mask_offset] & bitmask) != 0;

    DEBUG3(RELR, "is_tag %p:%s at line %u ", p, result ? "set" : "clear", line);
    return result;
}

static void set_tagged_type(uint tag_type, char **p) 
{
    *p += tag_type;
}
static void make_pi(char **p LINEDC)
{ENTER(make_pi)
    *p -= (size_t)(p);
    DEBUG2(RELR, "Making %p position indep at line %u", p, line);
}

typedef void (*zend_prepare_func_t)(void * TSRMLS_DC);

static void tag_zval_pp(zval **zp TSRMLS_DC);

/* Overview of hash_prepare. HashTables contain a number of internal pointers that are used to
   improve access efficiency, but that can be determinately regenerated by iterating over pListNext
   pointer chain. These are all zeroed during the prepare pass and regenerated during relocate. This
   improves timing of the relocate pass and reduces the size of the compressed module in the F/C. 

   Relocation needs a typed tag address to locate the HT. As some HTs are statically allocated in
   other structures (e.g. the function_table HT in zend_class_entry), the arBuckets field is 
   tagged as this occurs at a fixed offset from the start of the HT. 

   Since relocation is done on tagged pointers in ascending address order, we can't make assumptions 
   about this ordering (other than the arBuckets field has been relocated) HT relocation, so this
   uses MAKE_PI chaining which is independent of relocation of tagged pointers. */
static void hash_prepare(HashTable *ht, zend_prepare_func_t prepare_element TSRMLS_DC)
{ENTER(zend_hash_prepare)
	Bucket *p = ht->pListHead, *p_next;
	uint i;

    DEBUG4(RELR, "preparing HT %p (%u elements), %u buckets ptr %p ", ht, ht->nNumOfElements, ht->nTableSize, &ht->arBuckets);

    if (IS_TAGGED(ht->arBuckets)) {
        return;
    }

	if (ht->nNumOfElements) { 
	    while (1) {
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
		    TAG_NZ(p->arKey);
#endif
		    /* prepare the data structure pointed to by the pData pointer */
		    if (prepare_element) {
			    prepare_element(p->pData TSRMLS_CC);
		    }

            if (p->pDataPtr) {
                TAG(p->pDataPtr);
                p->pData = NULL;
            } else {
                TAG(p->pData);
            }

		    p->pLast     = NULL;
		    p->pNext     = NULL;
		    p->pListLast = NULL;
            if (!p->pListNext) {
                break;
            }
		    p_next       = p->pListNext; 
            MAKE_PI(p->pListNext);
            p            = p_next;
	    }

        ht->pListTail = NULL;
        MAKE_PI(ht->pListHead);
        MAKE_PI_NZ(ht->pInternalPointer);
        memset( ht->arBuckets, 0, ht->nTableSize * sizeof (Bucket *));
		TAG_TYPE(HASH, ht->arBuckets);

    } else if (ht->arBuckets) {
        /* Empty table with preallocated arBuckets vector (e.g. PHP < 5.4).  Nothing to do 
           apart from do an internal relocation on the arBuckets pointer */
		TAG(ht->arBuckets);
    }
/* prepared HT elements are never detroyed and the relevant "copy for execution" functions establish
   the correct destructor in the hash table copy */
	ht->pDestructor=NULL;
}

static inline void tag_zval_p(zval *z TSRMLS_DC)
{ENTER(tag_zval_p)
#if ZEND_EXTENSION_API_NO >= PHP_5_3_X_API_NO
	switch (z->type & IS_CONSTANT_TYPE_MASK) {
#else
	switch (z->type & ~IS_CONSTANT_INDEX) {
#endif
		case IS_STRING:
		case IS_CONSTANT:
			TAG(z->value.str.val);
			break;
		case IS_ARRAY:
		case IS_CONSTANT_ARRAY:
			HASH_PREPARE_P_ZVAL_PTR(z->value.ht);
			break;
	}
}

static void tag_zval_pp(zval **zp TSRMLS_DC)
{ENTER(tag_zval_pp)
	if (zp && !is_tag((char **)zp LINECC)) {
		TAG_ZVAL_P(*zp);
	}
}

static void prepare_op_array(zend_op_array *op_array TSRMLS_DC)
{ENTER(prepare_op_array)
    zend_op *opline;
    int i;

	if (op_array->type != ZEND_USER_FUNCTION) {
		return;
	}

    DEBUG3(RELR, "preparing op_array %p (%u oplines ptr %p) ", op_array, op_array->last, &op_array->opcodes);

	TAG_NZ(op_array->filename);

#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
	if (op_array->literals) {
        int i;
        for (i = 0; i < op_array->last_literal; i++) {
			TAG_ZVAL(op_array->literals[i].constant);
		}
    	TAG(op_array->literals);
	}
#endif

	if (op_array->opcodes && !IS_TAGGED(op_array->opcodes)) {
		for (opline = op_array->opcodes; opline < op_array->opcodes + op_array->last; opline++) {
        	opcode_handler_t handler = opline->handler;
            ZEND_VM_SET_OPCODE_HANDLER(opline);
            if (handler == opline->handler) {
                opline->handler = NULL;
            } else {
                opline->handler = handler;  /* return to original value */
                ZFCSG(absolute_externals) = 1; 
            }

			if (ZEND_OP1_TYPE(opline) == IS_CONST) {
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
				TAG(opline->op1.zv);
#else
				TAG_ZVAL(opline->op1.u.constant);
#endif
			}
			if (ZEND_OP2_TYPE(opline) == IS_CONST) {
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
                TAG(opline->op2.zv);
#else
				TAG_ZVAL(opline->op2.u.constant);
#endif
			}

			/* prepare jump targets */
			switch (opline->opcode) {
				case ZEND_JMP:
#if ZEND_EXTENSION_API_NO >= PHP_5_3_X_API_NO
				case ZEND_GOTO:
#endif
#if ZEND_EXTENSION_API_NO > PHP_5_4_X_API_NO
				case ZEND_FAST_CALL:
#endif
					TAG(ZEND_OP1(opline).jmp_addr);
					break;
				case ZEND_JMPZ:
				case ZEND_JMPNZ:
				case ZEND_JMPZ_EX:
				case ZEND_JMPNZ_EX:
#if ZEND_EXTENSION_API_NO >= PHP_5_3_X_API_NO
				case ZEND_JMP_SET:
#endif
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
				case ZEND_JMP_SET_VAR:
#endif
					TAG(ZEND_OP2(opline).jmp_addr);
					break;
			}
		}
	    TAG_TYPE(HANDLER, op_array->opcodes);
    }

	TAG_NZ(op_array->function_name);

	if (op_array->arg_info && !IS_TAGGED(op_array->arg_info)) {
        uint i;
		for (i = 0; i < op_array->num_args; i++) {
			TAG_NZ(op_array->arg_info[i].name);
			TAG_NZ(op_array->arg_info[i].class_name);
		}
		TAG(op_array->arg_info);
	}

	TAG_NZ(op_array->brk_cont_array);

	if (op_array->static_variables && !IS_TAGGED(op_array->static_variables)) {
		HASH_PREPARE_P_ZVAL_PTR(op_array->static_variables);
	}

	TAG_NZ(op_array->scope);
	TAG_NZ(op_array->doc_comment);
	TAG_NZ(op_array->try_catch_array);

	if (op_array->vars) {
		for (i = 0; i < op_array->last_var; i++) {
			TAG(op_array->vars[i].name);
		}
		TAG(op_array->vars);
	}

    TAG_NZ(op_array->prototype);
}

static void prepare_property_info(zend_property_info *prop TSRMLS_DC)
{ENTER(prepare_property_info)
	TAG(prop->name);
	TAG_NZ(prop->doc_comment);
	TAG_NZ(prop->ce);

}

static void prepare_class_entry(zend_class_entry **pce TSRMLS_DC)
{ENTER(prepare_class_entry)
	zend_class_entry *ce = *pce;
    int i, j;

	if (ce->type != ZEND_USER_CLASS) {
        return;
    }

    /* Don't tag since the *pce since it is already the pData target in a HT */

	TAG(ce->name);
	HASH_PREPARE(ce->function_table, prepare_op_array);
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
	if (ce->default_properties_table) {
		for (i = 0; i < ce->default_properties_count; i++) {
			if (ce->default_properties_table[i]) {
    			TAG_ZVAL_PP(ce->default_properties_table+i);
            }
		}
        TAG(ce->default_properties_table);
	}
	if (ce->default_static_members_table) {
		for (i = 0; i < ce->default_static_members_count; i++) {
			if (ce->default_static_members_table[i]) {
    			TAG_ZVAL_PP(ce->default_static_members_table+i);
            }
		}
        TAG(ce->default_static_members_table);
	}
 #else
	HASH_TAG_ZVAL_PTR(ce->default_properties);
	HASH_TAG_ZVAL_PTR(ce->default_static_members);
#endif
	HASH_TAG_ZVAL_PTR(ce->constants_table);

	TAG_NZ(ZEND_CE_FILENAME(ce));
	TAG_NZ(ZEND_CE_DOC_COMMENT(ce));

	HASH_PREPARE(ce->properties_info, prepare_property_info);

    TAG_NZ(ce->parent);  /// ?????????????  This should be zero !

    TAG_NZ(ce->constructor);
    TAG_NZ(ce->destructor);
    TAG_NZ(ce->clone);
    TAG_NZ(ce->__get);
    TAG_NZ(ce->__set);
    TAG_NZ(ce->__call);
    TAG_NZ(ce->serialize_func);
    TAG_NZ(ce->unserialize_func);
    TAG_NZ(ce->__isset);
    TAG_NZ(ce->__unset);
    TAG_NZ(ce->__tostring);
#if ZEND_EXTENSION_API_NO >= PHP_5_3_X_API_NO
    TAG_NZ(ce->__callstatic);
#endif

#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
// TODO: Need to check if ce->trait_aliases[i]->function needs touching on PHP 5.5
	if (ce->trait_aliases) {			
		for (i = 0; ce->trait_aliases[i]; i++) {
			if (ce->trait_aliases[i]->trait_method) {
				TAG_NZ(ce->trait_aliases[i]->trait_method->method_name);
				TAG_NZ(ce->trait_aliases[i]->trait_method->class_name);
				TAG_NZ(ce->trait_aliases[i]->trait_method);
			}
			TAG_NZ(ce->trait_aliases[i]->alias);
			TAG(ce->trait_aliases[i]);
		}
		TAG(ce->trait_aliases);
	}

	if (ce->trait_precedences) {
		for (i = 0; ce->trait_precedences[i]; i++) {
			TAG(ce->trait_precedences[i]->trait_method->method_name);
			TAG(ce->trait_precedences[i]->trait_method->class_name);
			TAG(ce->trait_precedences[i]->trait_method);

			if (ce->trait_precedences[i]->exclude_from_classes) {
				for (j = 0; ce->trait_precedences[i]->exclude_from_classes[j]; j++) {
					TAG(ce->trait_precedences[i]->exclude_from_classes[j]);
				}
				TAG(ce->trait_precedences[i]->exclude_from_classes);
			}

// TODO: Need to check if ce->trait_precedences[i]->function needs touching on PHP 5.5
			TAG(ce->trait_precedences[i]);
		}
		TAG(ce->trait_precedences);
	}
#endif
}

static void init_reloc_mask(zend_persistent_script *script)
{ENTER(init_reloc_mask)
    zend_uint size = (script->size+BYTES_PER_RELOC_MASK_BYTE-1)/BYTES_PER_RELOC_MASK_BYTE;
#ifdef ACCEL_DEBUG
    if (accel_directives_debug_flags & ACCEL_DBG_RELR) {
        ZFCSG(reloc_bitflag) = emalloc(ZEND_ALIGNED_SIZE(size) + script->size);
        ZFCSG(reloc_script_image) = (char *) ZFCSG(reloc_bitflag) + ZEND_ALIGNED_SIZE(size);
        memcpy(ZFCSG(reloc_script_image), script->mem, script->size);
    } else {
#else
    if (1) {
#endif  
       ZFCSG(reloc_bitflag) = emalloc(size);
    }
    memset(ZFCSG(reloc_bitflag), 0, size);
    ZFCSG(reloc_bitflag_size) = size;

    ZFCSG(module_base) = script->mem;
    ZFCSG(module_size) = script->size;
    ZFCSG(module_end)  = ZFCSG(module_base) + ZFCSG(module_size);
}

zend_uint zend_accel_script_prepare(zend_persistent_script *script, zend_uchar **rbvec TSRMLS_DC)
{ENTER(zend_accel_script_prepare)
	init_reloc_mask(script);
	HASH_PREPARE(script->function_table, prepare_op_array);
    HASH_PREPARE(script->class_table,  prepare_class_entry);
	prepare_op_array(&script->main_op_array TSRMLS_CC);
	TAG(script->full_path);
	TAG(script->mem);
    
	return zend_accel_prepare_memory(rbvec TSRMLS_CC);
}
