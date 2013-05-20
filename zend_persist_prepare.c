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

#define HANDLER_FLAG  0x01   /* Pointer to opcode handler routine */
#define INTERNAL_FLAG 0x02   /* Pointer to address within the module */
#define INTERN_FLAG   0x03   /* Pointer to address within the Interned string pool */
#define POINTER_FLAG  0x03   /* Either internal or intern.  Used as prepare_relocate arg */
#define FLAG_MASK     0x03

#define IS_RELOCATABLE(p) ((p) && !((size_t)p & FLAG_MASK))
#ifdef ACCEL_DEBUG
/* Function call used as error hook for debugging */ 
static void break_here(char **p){
	zend_accel_error(ACCEL_LOG_DEBUG, "Invalid reference to %p at %p", *p, p);
}
#  define BREAK_HERE(p) break_here(p);
#else
#  define BREAK_HERE(p)
#endif

#  define BYTES_PER_RELOC_MASK_BYTE (SIZEOF_SIZE_T * 8)

#define RELOCATE_INTERNAL(p) if (IS_RELOCATABLE(p)) {prepare_relocate((char **)&p, INTERNAL_FLAG);}
#define RELOCATE_INTERNAL_P(pp) if (IS_RELOCATABLE(*pp)) {prepare_relocate((char **)pp, INTERNAL_FLAG);}
#define RELOCATE_POINTER(p)  if (IS_RELOCATABLE(p)) {prepare_relocate((char **)&p, POINTER_FLAG);}
#define RELOCATE_POINTER_P(pp) if (IS_RELOCATABLE(*pp)) {prepare_relocate((char **)pp, POINTER_FLAG);}
#define RELOCATE_HANDLER(p)  if (IS_RELOCATABLE(p)) {prepare_relocate((char **)&p, HANDLER_FLAG);}
#define RELOCATE_HANDLER_P(pp)  if (IS_RELOCATABLE(*pp)) {prepare_relocate((char **)pp, HANDLER_FLAG);}

#define PREPARE_ZVAL(zv) prepare_zval_p(&zv TSRMLS_CC)
#define PREPARE_ZVAL_P(zvp) prepare_zval_p(zvp TSRMLS_CC); RELOCATE_INTERNAL(zvp); 
#define PREPARE_ZVAL_PP(zvpp) prepare_zval_pp(zvpp, NULL TSRMLS_CC)
#define HASH_PREPARE(ht, func) hash_prepare(&ht, (zend_prepare_func_t)func TSRMLS_CC)
#define HASH_PREPARE_P(htp, func) hash_prepare(htp, (zend_prepare_func_t)func TSRMLS_CC); RELOCATE_INTERNAL(htp)

#define HASH_PREPARE_ZVAL_PTR(ht) HASH_PREPARE(ht, prepare_zval_pp)
#define HASH_PREPARE_P_ZVAL_PTR(htp) HASH_PREPARE_P(htp, prepare_zval_pp)

static void prepare_relocate(char **p, int type) {
    uint size_t_offset;
    char bitflag_mask;

    size_t_offset = ((size_t *)p - (size_t *)ZFCSG(module_base));
    bitflag_mask  = 0x01<<(size_t_offset & 0x07 );

    /* calls to this func are predicated by IS_RELOCATABLE(p) so 2 lsb's are zero */
    if (((char *)p - ZFCSG(module_base)) < ZFCSG(module_size)
#if SIZEOF_SIZE_T == 8 
        || (size_t)p & (sizeof(size_t)-1)
#endif
        || ZFCSG(reloc_bitflag)[size_t_offset>>3] & bitflag_mask) {
        BREAK_HERE(p);  /* p is odd int aligned, outside module or already relocated */
    }

    if (type == HANDLER_FLAG) {
        /* there isn't an API to get the handler, so the easiest approach is the save, set, test 
           against saved and if nec restore */ 
        zend_op *opline = (zend_op *)p;    /* ALERT:  uses the fact that the handler is the fisrt elt! */
    	opcode_handler_t handler = opline->handler;
        ZEND_VM_SET_OPCODE_HANDLER(opline);
        if (handler == opline->handler) {
            *p = (char *) HANDLER_FLAG; /* default so overwrite with handler flag */
        } else {
            opline->handler = handler;  /* return to original value */
            ZFCSG(absolute_externals) = 1; 
        }
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
    } else if (type == POINTER_FLAG && IS_INTERNED(*p)) {
        *p -= (size_t) (CG(interned_strings_start) + INTERN_FLAG); 
#endif
    } else if ((*p - ZFCSG(module_base)) < ZFCSG(module_size)) {
        *p -= (size_t) (ZFCSG(module_base) + INTERNAL_FLAG);
    } else {
        BREAK_HERE(p);  /* p points to something funny to be explored */
        return;
    }

    ZFCSG(reloc_bitflag)[size_t_offset>>3] |= bitflag_mask;
}

typedef void (*zend_prepare_func_t)(void *, void* TSRMLS_DC);

static void prepare_zval_pp(zval **zp, void *dummy TSRMLS_DC);

static void hash_prepare(HashTable *ht, zend_prepare_func_t prepare_element TSRMLS_DC)
{ENTER(zend_hash_prepare)
	Bucket *p = ht->pListHead, *p_next;
	uint i;

	for (p = ht->pListHead; p; p = p_next) {
		p_next = p->pListNext;

#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
		RELOCATE_INTERNAL(p->arKey);
#endif
		/* persist the data itself */
		if (prepare_element) {
			prepare_element(p->pData, NULL TSRMLS_CC);
		}

        RELOCATE_INTERNAL(p->pDataPtr);
        RELOCATE_INTERNAL(p->pData);
		RELOCATE_INTERNAL(p->pLast);
		RELOCATE_INTERNAL(p->pNext);
		RELOCATE_INTERNAL(p->pListLast);
		RELOCATE_INTERNAL(p->pListNext);
		RELOCATE_INTERNAL(p);
	}

	RELOCATE_INTERNAL(ht->pListHead);
    RELOCATE_INTERNAL(ht->pListTail);
    RELOCATE_INTERNAL(ht->pInternalPointer);

	if (IS_RELOCATABLE(ht->arBuckets)) {
		if (ht->nNumOfElements) {
			for (i = 0; i < ht->nTableSize; i++) {
				RELOCATE_INTERNAL(ht->arBuckets[i]);
			}
		}
		RELOCATE_INTERNAL(ht->arBuckets);
    }
}

static inline void prepare_zval_p(zval *z TSRMLS_DC)
{ENTER(prepare_zval)
#if ZEND_EXTENSION_API_NO >= PHP_5_3_X_API_NO
	switch (z->type & IS_CONSTANT_TYPE_MASK) {
#else
	switch (z->type & ~IS_CONSTANT_INDEX) {
#endif
		case IS_STRING:
		case IS_CONSTANT:
			RELOCATE_POINTER(z->value.str.val);
			break;
		case IS_ARRAY:
		case IS_CONSTANT_ARRAY:
			HASH_PREPARE_P_ZVAL_PTR(z->value.ht);
			break;
	}
}

static void prepare_zval_pp(zval **zp, void *dummy TSRMLS_DC)
{ENTER(prepare_zval_pp)
    (void) dummy;
	if (IS_RELOCATABLE(*zp)) {
		PREPARE_ZVAL_P(*zp);
	}
}

static void prepare_op_array(zend_op_array *op_array, zend_persistent_script* main_persistent_script TSRMLS_DC)
{ENTER(prepare_op_array)
    uint i;
    zend_op *opline;

	if (op_array->type != ZEND_USER_FUNCTION) {
		return;
	}

	RELOCATE_POINTER(op_array->filename);

#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
	if (IS_RELOCATABLE(op_array->literals)) {
        for (i = 0; i < op_array->last_literal; i++) {
			PREPARE_ZVAL(op_array->literals[i].constant);
		}
    	RELOCATE_INTERNAL(op_array->literals);
	}
#endif

	if (IS_RELOCATABLE(op_array->opcodes)) {
		for (opline = op_array->opcodes; opline < op_array->opcodes + op_array->last; opline++) {
            RELOCATE_HANDLER(opline->handler);

			if (ZEND_OP1_TYPE(opline) == IS_CONST) {
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
				RELOCATE_INTERNAL(opline->op1.zv);
#else
				PREPARE_ZVAL(opline->op1.u.constant);
#endif
			}
			if (ZEND_OP2_TYPE(opline) == IS_CONST) {
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
                RELOCATE_INTERNAL(opline->op2.zv);
#else
				PREPARE_ZVAL(opline->op2.u.constant);
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
					RELOCATE_INTERNAL(ZEND_OP1(opline).jmp_addr);
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
					RELOCATE_INTERNAL(ZEND_OP2(opline).jmp_addr);
					break;
			}
		}

	    RELOCATE_INTERNAL(op_array->opcodes);
    }

	RELOCATE_POINTER(op_array->function_name);

	if (IS_RELOCATABLE(op_array->arg_info)) {
		for (i = 0; i < op_array->num_args; i++) {
			RELOCATE_INTERNED(op_array->arg_info[i].name);
			RELOCATE_INTERNED(op_array->arg_info[i].class_name);
		}
		RELOCATE_INTERNAL(op_array->arg_info);
	}

	RELOCATE_INTERNAL(op_array->brk_cont_array);

	if (IS_RELOCATABLE(op_array->static_variables)) {
		HASH_PREPARE_P_ZVAL_PTR(op_array->static_variables);
	}

	RELOCATE_INTERNAL(op_array->scope);
	RELOCATE_POINTER(op_array->doc_comment);
	RELOCATE_INTERNAL(op_array->try_catch_array);

	if (IS_RELOCATABLE(op_array->vars)) {
		for (i = 0; i < op_array->last_var; i++) {
			RELOCATE_POINTER(op_array->vars[i].name);
		}
		RELOCATE_INTERNAL(op_array->vars);
	}

    RELOCATE_INTERNAL(op_array->prototype);
}

static void zend_prepare_property_info(zend_property_info *prop, void* dummy TSRMLS_DC)
{ENTER(zend_prepare_property_info)
    (void) dummy;
	RELOCATE_INTERNED(prop->name);
	RELOCATE_INTERNAL(prop->doc_comment);
}

static int prepare_property_info_ce(zend_property_info *prop, void* dummy TSRMLS_DC)
{ENTER(prepare_property_info_ce)
    (void) dummy;
	RELOCATE_INTERNAL(prop->ce);
}

static void prepare_class_entry(zend_class_entry **pce, void* dummy TSRMLS_DC)
{ENTER(prepare_class_entry)
	zend_class_entry *ce = *pce;
    (void) dummy;
    int i, j;

	if (ce->type != ZEND_USER_CLASS) {
        return;
    }
	RELOCATE_INTERNAL(*pce);
	RELOCATE_POINTER(ce->name);
	HASH_PREPARE(ce->function_table, prepare_op_array);
#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
	if (ce->default_properties_table) {
		for (i = 0; i < ce->default_properties_count; i++) {
			PREPARE_ZVAL_PP(ce->default_properties_table+i);
		}
        RELOCATE_POINTER(ce->default_properties_table);
	}
	if (ce->default_static_members_table) {
		for (i = 0; i < ce->default_static_members_count; i++) {
			PREPARE_ZVAL_PP(ce->default_static_members_table+i);
		}
        RELOCATE_POINTER(ce->default_static_members_table);
	}
#else
	HASH_PREPARE_ZVAL_PTR(ce->default_properties);
	HASH_PREPARE_ZVAL_PTR(ce->default_static_members);
#endif
	HASH_PREPARE_ZVAL_PTR(ce->constants_table);

	RELOCATE_POINTER(ZEND_CE_FILENAME(ce));
	RELOCATE_POINTER(ZEND_CE_DOC_COMMENT(ce));

	HASH_PREPARE(ce->properties_info, zend_prepare_property_info);

    RELOCATE_INTERNAL(ce->parent);  /// ?????????????  This should be zero !

    RELOCATE_INTERNAL(ce->constructor);
    RELOCATE_INTERNAL(ce->destructor);
    RELOCATE_INTERNAL(ce->clone);
    RELOCATE_INTERNAL(ce->__get);
    RELOCATE_INTERNAL(ce->__set);
    RELOCATE_INTERNAL(ce->__call);
    RELOCATE_INTERNAL(ce->serialize_func);
    RELOCATE_INTERNAL(ce->unserialize_func);
    RELOCATE_INTERNAL(ce->__isset);
    RELOCATE_INTERNAL(ce->__unset);
    RELOCATE_INTERNAL(ce->__tostring);
#if ZEND_EXTENSION_API_NO >= PHP_5_3_X_API_NO
    RELOCATE_INTERNAL(ce->__callstatic);
#endif

#if ZEND_EXTENSION_API_NO > PHP_5_3_X_API_NO
// TODO: Need to check if ce->trait_aliases[i]->function needs touching on PHP 5.5
	if (ce->trait_aliases) {			
		for (i = 0; ce->trait_aliases[i]; i++) {
			if (IS_RELOCATABLE(ce->trait_aliases[i]->trait_method)) {
				RELOCATE_POINTER(ce->trait_aliases[i]->trait_method->method_name);
				RELOCATE_POINTER(ce->trait_aliases[i]->trait_method->class_name);
				RELOCATE_INTERNAL(ce->trait_aliases[i]->trait_method);
			}
			RELOCATE_INTERNAL(ce->trait_aliases[i]->alias);
			RELOCATE_INTERNAL(ce->trait_aliases[i]);
		}
		RELOCATE_INTERNAL(ce->trait_aliases);
	}

	if (ce->trait_precedences) {
		for (i = 0; ce->trait_precedences[i]; i++) {
			RELOCATE_POINTER(ce->trait_precedences[i]->trait_method->method_name);
			RELOCATE_POINTER(ce->trait_precedences[i]->trait_method->class_name);
			RELOCATE_INTERNAL(ce->trait_precedences[i]->trait_method);

			if (ce->trait_precedences[i]->exclude_from_classes) {
				for (j = 0; ce->trait_precedences[i]->exclude_from_classes[j]; j++) {
					RELOCATE_INTERNAL(ce->trait_precedences[i]->exclude_from_classes[j]);
				}
				RELOCATE_INTERNAL(ce->trait_precedences[i]->exclude_from_classes);
			}

// TODO: Need to check if ce->trait_precedences[i]->function needs touching on PHP 5.5
			RELOCATE_INTERNAL(ce->trait_precedences[i]);
		}
		RELOCATE_INTERNAL(ce->trait_precedences);
	}
#endif
}

static void init_reloc_mask(zend_persistent_script *script)
{ENTER(zend_prepare_init_reloc_mask)
    uint size = (script->size+BYTES_PER_RELOC_MASK_BYTE-1)/BYTES_PER_RELOC_MASK_BYTE;
#ifdef ACCEL_DEBUG
    if (accel_directives_debug_flags & ACCEL_DBG_RELR) {
        ZFCSG(reloc_bitflag) = emalloc(ZEND_ALIGNED_SIZE(size) + script->size);
        ZFCSG(reloc_script_image) = ZFCSG(reloc_bitflag) + ZEND_ALIGNED_SIZE(size);
        memcpy(ZFCSG(reloc_script_image), script->mem, script->size);
    } else {
#else
    if (1) {
#endif  
       ZFCSG(reloc_bitflag) = emalloc(size);
    }
    memset(ZFCSG(reloc_bitflag), 0, size);
    ZFCSG(reloc_bitflag_size) = size;
}
#ifdef ACCEL_DEBUG
//    ....
#else
//    ....
#endif  

zend_persistent_script *zend_accel_script_prepare(zend_persistent_script *script, char **key, unsigned int key_length TSRMLS_DC)
{ENTER(zend_accel_script_prepare)
	init_reloc_mask(script);
	HASH_PREPARE(script->function_table, prepare_op_array);
    HASH_PREPARE(script->class_table,  prepare_class_entry);
	prepare_op_array_ex(&script->main_op_array, script TSRMLS_CC);
	RELOCATE_INTERNAL(script->full_path);
	RELOCATE_INTERNAL(script->mem);

	return script;
}
