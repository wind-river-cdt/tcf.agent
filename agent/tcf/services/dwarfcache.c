/*******************************************************************************
 * Copyright (c) 2007, 2012 Wind River Systems, Inc. and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 * You may elect to redistribute this code under either of these licenses.
 *
 * Contributors:
 *     Wind River Systems - initial API and implementation
 *******************************************************************************/

/*
 * This module implements caching of DWARF debug information.
 *
 * Functions in this module use exceptions to report errors, see exceptions.h
 */

#include <tcf/config.h>

#if ENABLE_ELF && ENABLE_DebugContext

#include <assert.h>
#include <tcf/framework/exceptions.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/trace.h>
#include <tcf/services/dwarf.h>
#include <tcf/services/dwarfio.h>
#include <tcf/services/dwarfcache.h>
#include <tcf/services/dwarfexpr.h>
#include <tcf/services/stacktrace.h>

#define OBJ_HASH(Cache,ID) (((U4_T)(ID) + ((U4_T)(ID) >> 8)) % Cache->mObjectHashSize)

#define OBJECT_ARRAY_SIZE 128

/* Pseudo object IDs for fundamental types */
#define OBJECT_ID_VOID ((ContextAddress)-1)
#define OBJECT_ID_CHAR ((ContextAddress)-2)
#define OBJECT_ID_LAST ((ContextAddress)-8)

typedef struct ObjectArray {
    struct ObjectArray * mNext;
    ObjectInfo mArray[OBJECT_ARRAY_SIZE];
} ObjectArray;

typedef struct ObjectReference {
    ObjectInfo * obj;
    ObjectInfo * org;
} ObjectReference;

static DWARFCache * sCache;
static ELF_Section * sDebugSection;
static DIO_UnitDescriptor sUnitDesc;
static CompUnit * sCompUnit;
static ObjectInfo * sParentObject;
static ObjectInfo * sPrevSibling;
static ObjectReference * sObjRefs;
static U4_T sObjRefsCnt = 0;
static U4_T sObjRefsMax = 0;

static int sCloseListenerOK = 0;

unsigned calc_file_name_hash(const char * s) {
    unsigned l = strlen(s);
    unsigned h = 0;
    while (l > 0) {
        unsigned g;
        unsigned char ch = s[--l];
        if (ch == '/') break;
        if (ch == '\\') break;
        h = (h << 4) + ch;
        g = h & 0xf0000000;
        if (g) h = (h ^ (g >> 24)) & ~g;
    }
    return h;
}

static ObjectInfo * add_object_info(ContextAddress ID) {
    U4_T Hash = OBJ_HASH(sCache, ID);
    ObjectInfo * Info = sCache->mObjectHash[Hash];
    while (Info != NULL) {
        if (Info->mID == ID) return Info;
        Info = Info->mHashNext;
    }
    if (ID < OBJECT_ID_LAST) {
        if (ID < sDebugSection->addr) str_exception(ERR_INV_DWARF, "Invalid entry reference");
        if (ID > sDebugSection->addr + sDebugSection->size) str_exception(ERR_INV_DWARF, "Invalid entry reference");
    }
    if (sCache->mObjectArrayPos >= OBJECT_ARRAY_SIZE) {
        ObjectArray * Buf = (ObjectArray *)loc_alloc_zero(sizeof(ObjectArray));
        Buf->mNext = sCache->mObjectList;
        sCache->mObjectList = Buf;
        sCache->mObjectArrayPos = 0;
    }
    Info = sCache->mObjectList->mArray + sCache->mObjectArrayPos++;
    Info->mHashNext = sCache->mObjectHash[Hash];
    sCache->mObjectHash[Hash] = Info;
    Info->mID = ID;
    return Info;
}

static CompUnit * add_comp_unit(ContextAddress ID) {
    ObjectInfo * Info = add_object_info(ID);
    if (Info->mCompUnit == NULL) {
        CompUnit * Unit = (CompUnit *)loc_alloc_zero(sizeof(CompUnit));
        Unit->mObject = Info;
        Info->mCompUnit = Unit;
    }
    return Info->mCompUnit;
}

static CompUnit * find_comp_unit(ContextAddress ObjID) {
    if (sCompUnit != NULL) {
        ContextAddress ID = sCompUnit->mDesc.mSection->addr + sCompUnit->mDesc.mUnitOffs;
        if (ID <= ObjID && ID + sCompUnit->mDesc.mUnitSize > ObjID) return sCompUnit;
    }
    if (sCache->mCompUnitsIndex != NULL) {
        unsigned l = 0;
        unsigned h = sCache->mCompUnitsCnt;
        while (l < h) {
            unsigned i = (l + h) / 2;
            CompUnit * unit = sCache->mCompUnitsIndex[i];
            ContextAddress ID = unit->mDesc.mSection->addr + unit->mDesc.mUnitOffs;
            if (ID > ObjID) {
                h = i;
            }
            else if (ID + unit->mDesc.mUnitSize <= ObjID) {
                l = i + 1;
            }
            else {
                return unit;
            }
        }
    }
    return NULL;
}

static void read_object_info(U2_T Tag, U2_T Attr, U2_T Form);
static void read_object_refs(void);

ObjectInfo * find_object(DWARFCache * Cache, ContextAddress ID) {
    ObjectInfo * Info = Cache->mObjectHash[OBJ_HASH(Cache, ID)];
    while (Info != NULL) {
        if (Info->mID == ID) return Info;
        Info = Info->mHashNext;
    }
#if ENABLE_DWARF_LAZY_LOAD
    sCache = Cache;
    sCompUnit = NULL;
    sCompUnit = find_comp_unit(ID);
    if (sCompUnit != NULL) {
        Trap trap;
        sUnitDesc = sCompUnit->mDesc;
        sDebugSection = sUnitDesc.mSection;
        sParentObject = NULL;
        sPrevSibling = NULL;
        dio_EnterSection(&sCompUnit->mDesc, sDebugSection, ID - sDebugSection->addr);
        if (set_trap(&trap)) {
            dio_ReadEntry(read_object_info, 0);
            Info = Cache->mObjectHash[OBJ_HASH(Cache, ID)];
            while (Info != NULL) {
                if (Info->mID == ID) break;
                Info = Info->mHashNext;
            }
            clear_trap(&trap);
        }
        dio_ExitSection();
        sDebugSection = NULL;
        read_object_refs();
    }
    sCompUnit = NULL;
#endif
    return Info;
}

static ObjectInfo * find_loaded_object(DWARFCache * Cache, ContextAddress ID) {
    ObjectInfo * Info = Cache->mObjectHash[OBJ_HASH(Cache, ID)];
    while (Info != NULL) {
        if (Info->mID == ID) return Info;
        Info = Info->mHashNext;
    }
    return NULL;
}

static void add_object_reference(ObjectInfo * org, ObjectInfo * obj) {
#if ENABLE_DWARF_LAZY_LOAD
    if (org->mTag != 0 && obj == NULL) return;
#else
    if (obj == NULL) return;
#endif
    if (org->mCompUnit == NULL) org->mCompUnit = find_comp_unit(org->mID);
    if (sObjRefsCnt >= sObjRefsMax) {
        sObjRefsMax += sObjRefsMax ? sObjRefsMax * 2 : 256;
        sObjRefs = (ObjectReference *)loc_realloc(sObjRefs, sizeof(ObjectReference) * sObjRefsMax);
    }
    if (obj != NULL) obj->mFlags |= DOIF_load_mark;
    sObjRefs[sObjRefsCnt].org = org;
    sObjRefs[sObjRefsCnt].obj = obj;
    sObjRefsCnt++;
}

static U4_T get_fund_type_size(CompUnit * Unit, U2_T ft) {
    switch (ft) {
    case FT_char          :
    case FT_signed_char   :
    case FT_unsigned_char :
        return 1;
    case FT_short         :
    case FT_signed_short  :
    case FT_unsigned_short:
        return 2;
    case FT_integer       :
    case FT_signed_integer:
    case FT_unsigned_integer:
        return 4;
    case FT_long          :
    case FT_signed_long   :
    case FT_unsigned_long :
        return Unit->mFile->elf64 ? 8 : 4;
    case FT_pointer       :
        return Unit->mDesc.mAddressSize;
    case FT_float         :
        return 4;
    case FT_dbl_prec_float:
        return 8;
    case FT_complex       :
        return 8;
    case FT_dbl_prec_complex:
        return 16;
    case FT_boolean       :
        return 4;
    case FT_void          :
        return 0;
    }
    str_exception(ERR_INV_DWARF, "Invalid fundamental type code");
    return 0;
}

static void read_mod_fund_type(U2_T Form, ObjectInfo ** Type) {
    U1_T * Buf;
    size_t BufSize;
    size_t BufPos;
    int i;
    U2_T FT = 0;
    dio_ChkBlock(Form, &Buf, &BufSize);
    for (i = 0; i < 2; i++) {
        FT |= (U2_T)Buf[BufSize - 2 +
            (sDebugSection->file->big_endian ? 1 - i : i)] << (i * 8);
    }
    *Type = add_object_info((ContextAddress)(sDebugSection->addr + dio_GetPos() - 2));
    (*Type)->mTag = TAG_fund_type;
    (*Type)->mCompUnit = sCompUnit;
    (*Type)->u.mFundType = FT;
    BufPos = BufSize - 2;
    while (BufPos > 0) {
        U2_T Tag = 0;
        ObjectInfo * Mod = NULL;
        switch (Buf[--BufPos]) {
        case MOD_volatile:
        case MOD_const:
            continue;
        case MOD_pointer_to:
            Tag = TAG_mod_pointer;
            break;
        case MOD_reference_to:
            Tag = TAG_mod_reference;
            break;
        default:
            str_exception(ERR_INV_DWARF, "Invalid type modifier code");
        }
        Mod = add_object_info((ContextAddress)(sDebugSection->addr + dio_GetPos() - BufSize + BufPos));
        Mod->mTag = Tag;
        Mod->mCompUnit = sCompUnit;
        Mod->mType = *Type;
        *Type = Mod;
    }
}

static void read_mod_user_def_type(U2_T Form, ObjectInfo ** Type) {
    U1_T * Buf;
    size_t BufSize;
    size_t BufPos;
    int i;
    U4_T Ref = 0;
    dio_ChkBlock(Form, &Buf, &BufSize);
    for (i = 0; i < 4; i++) {
        Ref |= (U4_T)Buf[BufSize - 4 +
            (sDebugSection->file->big_endian ? 3 - i : i)] << (i * 8);
    }
    *Type = add_object_info((ContextAddress)(sDebugSection->addr + Ref));
    add_object_reference(*Type, NULL);
    BufPos = BufSize - 4;
    while (BufPos > 0) {
        U2_T Tag = 0;
        ObjectInfo * Mod = NULL;
        switch (Buf[--BufPos]) {
        case MOD_volatile:
        case MOD_const:
            continue;
        case MOD_pointer_to:
            Tag = TAG_mod_pointer;
            break;
        case MOD_reference_to:
            Tag = TAG_mod_reference;
            break;
        default:
            str_exception(ERR_INV_DWARF, "Invalid type modifier code");
        }
        Mod = add_object_info((ContextAddress)(sDebugSection->addr + dio_GetPos() - BufSize + BufPos));
        Mod->mTag = Tag;
        Mod->mCompUnit = sCompUnit;
        Mod->mType = *Type;
        *Type = Mod;
    }
}

static I8_T read_long_value(void) {
    switch (get_fund_type_size(sCompUnit, FT_long)) {
    case 4: return (I4_T)dio_ReadU4();
    case 8: return (I8_T)dio_ReadU8();
    }
    str_exception(ERR_OTHER, "Invalid size of long int");
    return 0;
}

static void read_subscr_data(U2_T Form, ObjectInfo * Array) {
    U1_T * Buf;
    size_t BufSize;
    U8_T BufEnd = 0;
    U8_T OrgPos = dio_GetPos();
    ObjectInfo ** Children = &Array->mChildren;

    assert(Array->mChildren == NULL);
    assert(Array->mType == NULL);

    dio_ChkBlock(Form, &Buf, &BufSize);
    dio_SetPos(Buf - (U1_T *)sDebugSection->data);
    BufEnd = dio_GetPos() + BufSize;
    while (dio_GetPos() < BufEnd) {
        ObjectInfo * Type = NULL;
        U1_T Fmt = dio_ReadU1();
        switch (Fmt) {
        case FMT_FT_C_C:
        case FMT_FT_C_X:
        case FMT_FT_X_C:
        case FMT_FT_X_X:
            Type = add_object_info((ContextAddress)(sDebugSection->addr + dio_GetPos()));
            Type->mTag = TAG_fund_type;
            Type->mCompUnit = sCompUnit;
            Type->u.mFundType = dio_ReadU2();
            break;
        case FMT_UT_C_C:
        case FMT_UT_C_X:
        case FMT_UT_X_C:
        case FMT_UT_X_X:
            dio_ReadAttribute(AT_subscr_data, FORM_REF);
            Type = add_object_info((ContextAddress)dio_gFormData);
            add_object_reference(Type, NULL);
            break;
        }
        if (Type != NULL) {
            ObjectInfo * Range = add_object_info((ContextAddress)(sDebugSection->addr + dio_GetPos()));
            Range->mTag = TAG_index_range;
            Range->mCompUnit = sCompUnit;
            Range->mType = Type;
            Range->u.mRange.mFmt = Fmt;
            switch (Fmt) {
            case FMT_FT_C_C:
            case FMT_FT_C_X:
            case FMT_UT_C_C:
            case FMT_UT_C_X:
                Range->u.mRange.mLow.mValue = read_long_value();
                break;
            case FMT_FT_X_C:
            case FMT_FT_X_X:
            case FMT_UT_X_C:
            case FMT_UT_X_X:
                dio_ReadAttribute(0, FORM_BLOCK2);
                Range->u.mRange.mLow.mExpr.mAddr = (U1_T *)dio_gFormDataAddr;
                Range->u.mRange.mLow.mExpr.mSize = dio_gFormDataSize;
                break;
            }
            switch (Fmt) {
            case FMT_FT_C_C:
            case FMT_FT_X_C:
            case FMT_UT_C_C:
            case FMT_UT_X_C:
                Range->u.mRange.mHigh.mValue = read_long_value();
                break;
            case FMT_FT_C_X:
            case FMT_FT_X_X:
            case FMT_UT_C_X:
            case FMT_UT_X_X:
                dio_ReadAttribute(0, FORM_BLOCK2);
                Range->u.mRange.mHigh.mExpr.mAddr = (U1_T *)dio_gFormDataAddr;
                Range->u.mRange.mHigh.mExpr.mSize = dio_gFormDataSize;
                break;
            }
            *Children = Range;
            Children = &Range->mSibling;
        }
        else if (Fmt == FMT_ET) {
            U2_T x = dio_ReadU2();
            U2_T Attr = (x & 0xfff0u) >> 4;
            U2_T Form = x & 0xfu;
            dio_ReadAttribute(Attr, Form);
            switch (Attr) {
            case AT_fund_type:
                dio_ChkData(Form);
                Type = add_object_info((ContextAddress)(sDebugSection->addr + dio_GetPos() - dio_gFormDataSize));
                Type->mTag = TAG_fund_type;
                Type->mCompUnit = sCompUnit;
                Type->u.mFundType = (U2_T)dio_gFormData;
                break;
            case AT_user_def_type:
                dio_ChkRef(Form);
                Type = add_object_info((ContextAddress)dio_gFormData);
                add_object_reference(Type, NULL);
                break;
            case AT_mod_fund_type:
                read_mod_fund_type(Form, &Type);
                break;
            case AT_mod_u_d_type:
                read_mod_user_def_type(Form, &Type);
                break;
            default:
                str_exception(ERR_INV_DWARF, "Invalid array element type format");
            }
            Array->mType = Type;
        }
        else {
            str_exception(ERR_INV_DWARF, "Invalid array subscription format");
        }
    }
    dio_SetPos(OrgPos);
}

static void read_object_info(U2_T Tag, U2_T Attr, U2_T Form) {
    static ObjectInfo * Info;
    static U8_T Sibling;
    static int HasChildren;
    static int Skip;

    if (Skip && Attr && Attr != AT_sibling) return;

    switch (Attr) {
    case 0:
        if (Form) {
            if (Tag == TAG_compile_unit) {
                CompUnit * Unit = add_comp_unit((ContextAddress)(sDebugSection->addr + dio_gEntryPos));
                assert(sParentObject == NULL);
                Unit->mFile = sCache->mFile;
                Unit->mRegIdScope.big_endian = sCache->mFile->big_endian;
                Unit->mRegIdScope.machine = sCache->mFile->machine;
                Unit->mRegIdScope.os_abi = sCache->mFile->os_abi;
                Unit->mRegIdScope.elf64 = sCache->mFile->elf64;
                Unit->mRegIdScope.id_type = REGNUM_DWARF;
                Info = Unit->mObject;
                assert(Info->mTag == 0);
                sCompUnit = Unit;
            }
            else {
                Info = add_object_info((ContextAddress)(sDebugSection->addr + dio_gEntryPos));
            }
            if (sParentObject) Info->mParent = sParentObject;
            HasChildren = Form == DWARF_ENTRY_HAS_CHILDREN;
            Sibling = 0;
            Skip = Info->mTag != 0;
            if (Skip) {
                /* Object is already loaded */
                assert(Info->mTag == Tag);
                assert(Tag != TAG_compile_unit);
                assert(Info->mCompUnit == sCompUnit);
                return;
            }
            Info->mTag = Tag;
            Info->mCompUnit = sCompUnit;
        }
        else {
            switch (Tag) {
            case TAG_compile_unit:
                assert(sCache->mCompUnitsIndex == NULL);
                if (Sibling == 0) Sibling = sUnitDesc.mUnitOffs + sUnitDesc.mUnitSize;
                sCompUnit->mDesc = sUnitDesc;
                sCache->mCompUnitsCnt++;
                break;
            case TAG_global_subroutine:
            case TAG_inlined_subroutine:
            case TAG_subroutine:
            case TAG_subprogram:
            case TAG_entry_point:
            case TAG_pointer_type:
            case TAG_mod_pointer:
            case TAG_const_type:
            case TAG_volatile_type:
                if (Info->mType == NULL) {
                    /* NULL here means "void" */
                    Info->mType = add_object_info(OBJECT_ID_VOID);
                    if (Info->mType->mTag == 0) {
                        Info->mType->mTag = TAG_fund_type;
                        Info->mType->mCompUnit = sCompUnit;
                        Info->mType->u.mFundType = FT_void;
                    }
                }
                break;
            case TAG_string_type:
                if (Info->mType == NULL) {
                    /* NULL here means "char" */
                    Info->mType = add_object_info(OBJECT_ID_CHAR);
                    if (Info->mType->mTag == 0) {
                        Info->mType->mTag = TAG_fund_type;
                        Info->mType->mCompUnit = sCompUnit;
                        Info->mType->u.mFundType = FT_char;
                    }
                }
                break;
            }
            if (sPrevSibling != NULL) sPrevSibling->mSibling = Info;
            else if (sParentObject != NULL) sParentObject->mChildren = Info;
            else if (Tag == TAG_compile_unit) sCache->mCompUnits = Info;
            sPrevSibling = Info;
            if (Skip && Sibling != 0) {
                dio_SetPos(Sibling);
                return;
            }
            if (Tag == TAG_enumerator && Info->mType == NULL) Info->mType = sParentObject;
#if ENABLE_DWARF_LAZY_LOAD
            if (Sibling != 0) {
                switch (Tag) {
                case TAG_union_type:
                case TAG_array_type:
                case TAG_class_type:
                case TAG_structure_type:
                case TAG_subroutine_type:
                case TAG_global_subroutine:
                case TAG_subroutine:
                case TAG_subprogram:
                case TAG_namespace:
                    dio_SetPos(Sibling);
                    return;
                }
            }
#endif
            Info->mFlags |= DOIF_children_loaded;
            if (Sibling != 0 || HasChildren) {
                U8_T SiblingPos = Sibling;
                ObjectInfo * Parent = sParentObject;
                ObjectInfo * PrevSibling = sPrevSibling;
                sParentObject = Info;
                sPrevSibling = NULL;
                for (;;) {
                    if (SiblingPos > 0 && dio_GetPos() >= SiblingPos) break;
                    if (!dio_ReadEntry(read_object_info, 0)) break;
                }
                if (SiblingPos > dio_GetPos()) dio_SetPos(SiblingPos);
                sParentObject = Parent;
                sPrevSibling = PrevSibling;
            }
        }
        break;
    case AT_sibling:
        dio_ChkRef(Form);
        Sibling = dio_gFormData - sDebugSection->addr;
        break;
    case AT_type:
        dio_ChkRef(Form);
        Info->mType = add_object_info((ContextAddress)dio_gFormData);
        add_object_reference(Info->mType, NULL);
        break;
    case AT_fund_type:
        dio_ChkData(Form);
        Info->mType = add_object_info((ContextAddress)(sDebugSection->addr + dio_GetPos() - dio_gFormDataSize));
        Info->mType->mTag = TAG_fund_type;
        Info->mType->mCompUnit = sCompUnit;
        Info->mType->u.mFundType = (U2_T)dio_gFormData;
        break;
    case AT_user_def_type:
        dio_ChkRef(Form);
        Info->mType = add_object_info((ContextAddress)dio_gFormData);
        add_object_reference(Info->mType, NULL);
        break;
    case AT_mod_fund_type:
        read_mod_fund_type(Form, &Info->mType);
        break;
    case AT_mod_u_d_type:
        read_mod_user_def_type(Form, &Info->mType);
        break;
    case AT_encoding:
        if (Tag == TAG_base_type) {
            Info->u.mFundType = (U2_T)dio_gFormData;
        }
        break;
    case AT_subscr_data:
        read_subscr_data(Form, Info);
        break;
    case AT_name:
        dio_ChkString(Form);
        if (*(char *)dio_gFormDataAddr) Info->mName = (char *)dio_gFormDataAddr;
        break;
    case AT_specification_v2:
        dio_ChkRef(Form);
        add_object_reference(add_object_info((ContextAddress)dio_gFormData), Info);
        Info->mFlags |= DOIF_specification;
        break;
    case AT_abstract_origin:
        dio_ChkRef(Form);
        add_object_reference(add_object_info((ContextAddress)dio_gFormData), Info);
        Info->mFlags |= DOIF_abstract_origin;
        break;
    case AT_extension:
        dio_ChkRef(Form);
        add_object_reference(add_object_info((ContextAddress)dio_gFormData), Info);
        Info->mFlags |= DOIF_extension;
        break;
    case AT_MIPS_linkage_name:
        Info->mFlags |= DOIF_linkage_name;
        break;
    case AT_mangled:
        Info->mFlags |= DOIF_mangled_name;
        break;
    case AT_low_pc:
        dio_ChkAddr(Form);
        Info->u.mCode.mLowPC = (ContextAddress)dio_gFormData;
        if (dio_gFormSection) Info->u.mCode.mSection = dio_gFormSection;
        Info->mFlags |= DOIF_low_pc;
        break;
    case AT_high_pc:
        dio_ChkAddr(Form);
        if (Info->mFlags & DOIF_ranges) break;
        Info->u.mCode.mHighPC.mAddr = (ContextAddress)dio_gFormData;
        if (dio_gFormSection) Info->u.mCode.mSection = dio_gFormSection;
        break;
    case AT_ranges:
        dio_ChkData(Form);
        Info->u.mCode.mHighPC.mRanges = dio_gFormData;
        Info->mFlags |= DOIF_ranges;
        break;
    case AT_external:
        dio_ChkFlag(Form);
        if (dio_gFormData) Info->mFlags |= DOIF_external;
        break;
    case AT_artificial:
        dio_ChkFlag(Form);
        if (dio_gFormData) Info->mFlags |= DOIF_artificial;
        break;
    case AT_declaration:
        dio_ChkFlag(Form);
        if (dio_gFormData) Info->mFlags |= DOIF_declaration;
        break;
    case AT_private:
        if (Form == FORM_STRING) {
            /* Diab 4.1 */
            Info->mFlags |= DOIF_private;
            break;
        }
        dio_ChkFlag(Form);
        if (dio_gFormData) Info->mFlags |= DOIF_private;
        break;
    case AT_protected:
        if (Form == FORM_STRING) {
            /* Diab 4.1 */
            Info->mFlags |= DOIF_protected;
            break;
        }
        dio_ChkFlag(Form);
        if (dio_gFormData) Info->mFlags |= DOIF_protected;
        break;
    case AT_public:
        if (Form == FORM_STRING) {
            /* Diab 4.1 */
            Info->mFlags |= DOIF_public;
            break;
        }
        dio_ChkFlag(Form);
        if (dio_gFormData) Info->mFlags |= DOIF_public;
        break;
    case AT_location:
    case AT_string_length:
        if (Form == FORM_DATA4 || Form == FORM_DATA8 || Form == FORM_SEC_OFFSET || Tag == TAG_formal_parameter) {
            Info->mFlags |= DOIF_need_frame;
        }
        break;
    }
    if (Tag == TAG_compile_unit) {
        CompUnit * Unit = Info->mCompUnit;
        switch (Attr) {
        case AT_low_pc:
            Unit->mTextSection = dio_gFormSection;
            break;
        case AT_comp_dir:
            dio_ChkString(Form);
            Unit->mDir = (char *)dio_gFormDataAddr;
            break;
        case AT_stmt_list:
            dio_ChkData(Form);
            Unit->mLineInfoOffs = dio_gFormData;
            break;
        case AT_base_types:
            Unit->mBaseTypes = add_comp_unit((ContextAddress)dio_gFormData);
            break;
        case AT_language:
            dio_ChkData(Form);
            Unit->mLanguage = (U2_T)dio_gFormData;
            break;
        }
    }
}

static int object_references_comparator(const void * x, const void * y) {
    ObjectReference * rx = (ObjectReference *)x;
    ObjectReference * ry = (ObjectReference *)y;
    if (rx->obj == ry->obj) return 0;
    if (rx->obj == NULL) return -1;
    if (ry->obj == NULL) return +1;
    if (rx->obj == ry->org) return -1;
    if (rx->org == ry->obj) return +1;
    if (rx->obj->mID < ry->obj->mID) return -1;
    if (rx->obj->mID > ry->obj->mID) return +1;
    return 0;
}

static void read_object_refs(void) {
    U4_T pos = 0;
#if ENABLE_DWARF_LAZY_LOAD
    /*
     * Build transitive closure of DWARF objects graph:
     * load objects that are referenced by already loaded objects.
     */
    sCompUnit = NULL;
    while (pos < sObjRefsCnt) {
        ObjectReference ref = sObjRefs[pos++];
        if (ref.org->mCompUnit == NULL) ref.org->mCompUnit = find_comp_unit(ref.org->mID);
        if (ref.org->mTag == 0) {
            Trap trap;
            ObjectInfo * obj = ref.org;
            sCompUnit = obj->mCompUnit;
            sUnitDesc = sCompUnit->mDesc;
            sDebugSection = sUnitDesc.mSection;
            sParentObject = NULL;
            sPrevSibling = NULL;
            dio_EnterSection(&sCompUnit->mDesc, sDebugSection, obj->mID - sDebugSection->addr);
            if (set_trap(&trap)) {
                dio_ReadEntry(read_object_info, 0);
                clear_trap(&trap);
            }
            dio_ExitSection();
            sDebugSection = NULL;
            sCompUnit = NULL;
            if (trap.error) exception(trap.error);
        }
    }
    pos = 0;
#endif
    /*
     * Propagate attributes like mName and mType along chain of references.
     */
    qsort(sObjRefs, sObjRefsCnt, sizeof(ObjectReference), object_references_comparator);
    while (pos < sObjRefsCnt) {
        ObjectReference ref = sObjRefs[pos++];
        if (ref.obj != NULL) {
            assert(ref.org->mTag != 0);
            if (ref.org->mFlags & DOIF_load_mark) str_fmt_exception(ERR_INV_DWARF,
                "Invalid forward reference at %x", (unsigned)ref.obj->mID);
            if (ref.obj->mName == NULL) ref.obj->mName = ref.org->mName;
            if (ref.obj->mType == NULL) ref.obj->mType = ref.org->mType;
            ref.obj->mFlags |= ref.org->mFlags & ~(DOIF_children_loaded | DOIF_declaration | DOIF_specification);
            if (ref.obj->mFlags & DOIF_specification) {
                ref.org->mDefinition = ref.obj;
                if ((ref.obj->mFlags & (DOIF_low_pc | DOIF_ranges)) == 0) {
                    ref.obj->mFlags |= ref.org->mFlags & DOIF_declaration;
                }
            }
            if (ref.obj->mFlags & DOIF_abstract_origin) {
                if ((ref.obj->mTag == TAG_variable && (ref.obj->mFlags & DOIF_external)) ||
                        ref.obj->mTag == TAG_subprogram ||
                        (ref.obj->mTag == TAG_formal_parameter && ref.obj->mParent != NULL && ref.obj->mParent->mTag == TAG_subprogram))
                    ref.org->mDefinition = ref.obj;
            }
            if (ref.obj->mFlags & DOIF_external) {
                ObjectInfo * cls = ref.org;
                while (cls->mParent != NULL &&
                    (cls->mParent->mTag == TAG_class_type || cls->mParent->mTag == TAG_structure_type)) {
                    cls = cls->mParent;
                }
                cls->mFlags |= DOIF_external;
            }
            ref.obj->mFlags &= ~DOIF_load_mark;
        }
    }
    sObjRefsCnt = 0;
}

static int addr_ranges_comparator(const void * x, const void * y) {
    UnitAddressRange * rx = (UnitAddressRange *)x;
    UnitAddressRange * ry = (UnitAddressRange *)y;
    if (rx->mSection < ry->mSection) return -1;
    if (rx->mSection > ry->mSection) return +1;
    if (rx->mAddr < ry->mAddr) return -1;
    if (rx->mAddr > ry->mAddr) return +1;
    if (rx->mUnit->mObject->mID < ry->mUnit->mObject->mID) return -1;
    if (rx->mUnit->mObject->mID > ry->mUnit->mObject->mID) return +1;
    return 0;
}

static void add_addr_range(ELF_Section * sec, CompUnit * unit, ContextAddress addr, ContextAddress size) {
    UnitAddressRange * range = NULL;
    if (sCache->mAddrRangesCnt >= sCache->mAddrRangesMax) {
        sCache->mAddrRangesMax = sCache->mAddrRangesMax == 0 ? 64 : sCache->mAddrRangesMax * 2;
        sCache->mAddrRanges = (UnitAddressRange *)loc_realloc(sCache->mAddrRanges, sizeof(UnitAddressRange) * sCache->mAddrRangesMax);
    }
    range = sCache->mAddrRanges + sCache->mAddrRangesCnt++;
    memset(range, 0, sizeof(UnitAddressRange));
    if (sec != NULL) {
        assert(sec->file == sCache->mFile);
        range->mSection = sec->index;
        sCache->mAddrRangesRelocatable = 1;
    }
    range->mAddr = addr;
    range->mSize = size;
    range->mUnit = unit;
}

static void load_addr_ranges(void) {
    Trap trap;
    unsigned idx;
    ELF_File * file = sCache->mFile;
    ELF_Section * debug_ranges = NULL;

    memset(&trap, 0, sizeof(trap));
    for (idx = 1; idx < file->section_cnt; idx++) {
        ELF_Section * sec = file->sections + idx;
        if (sec->size == 0) continue;
        if (sec->name == NULL) continue;
        if (strcmp(sec->name, ".debug_ranges") == 0) {
            debug_ranges = sec;
        }
        else if (strcmp(sec->name, ".debug_aranges") == 0) {
            sCompUnit = NULL;
            dio_EnterSection(NULL, sec, 0);
            if (set_trap(&trap)) {
                while (dio_GetPos() < sec->size) {
                    int dwarf64 = 0;
                    U8_T size = dio_ReadU4();
                    U8_T next = 0;
                    if (size == 0xffffffffu) {
                        dwarf64 = 1;
                        size = dio_ReadU8();
                    }
                    next = dio_GetPos() + size;
                    if (dio_ReadU2() != 2) {
                        dio_SetPos(next);
                    }
                    else {
                        U8_T offs = dio_ReadAddressX(NULL, dwarf64 ? 8 : 4);
                        U1_T addr_size = dio_ReadU1();
                        U1_T segm_size = dio_ReadU1();
                        if (segm_size != 0) str_exception(ERR_INV_DWARF, "segment descriptors are not supported");
                        sCompUnit = find_comp_unit((ContextAddress)offs);
                        if (sCompUnit == NULL) str_exception(ERR_INV_DWARF, "invalid .debug_aranges section");
                        sCompUnit->mObject->mFlags |= DOIF_aranges;
                        while (dio_GetPos() % (addr_size * 2) != 0) dio_Skip(1);
                        for (;;) {
                            ELF_Section * addr_sec = NULL;
                            ELF_Section * size_sec = NULL;
                            ContextAddress addr = (ContextAddress)dio_ReadAddressX(&addr_sec, addr_size);
                            ContextAddress size = (ContextAddress)dio_ReadAddressX(&size_sec, addr_size);
                            if (addr == 0 && size == 0) break;
                            if (size == 0) continue;
                            add_addr_range(addr_sec, sCompUnit, addr, size);
                        }
                    }
                }
                clear_trap(&trap);
            }
            dio_ExitSection();
            if (trap.error) break;
        }
    }
    if (trap.error) exception(trap.error);
    if (sCache->mCompUnits != NULL) {
        ObjectInfo * info = sCache->mCompUnits;
        while (info != NULL) {
            if (info->mFlags & DOIF_low_pc) {
                CompUnit * unit = info->mCompUnit;
                ContextAddress base = info->u.mCode.mLowPC;
                if (info->mFlags & DOIF_ranges) {
                    if (debug_ranges != NULL) {
                        dio_EnterSection(&unit->mDesc, debug_ranges, info->u.mCode.mHighPC.mRanges);
                        for (;;) {
                            ELF_Section * sec_x = NULL;
                            ELF_Section * sec_y = NULL;
                            U8_T x = dio_ReadAddress(&sec_x);
                            U8_T y = dio_ReadAddress(&sec_y);
                            if (x == 0 && y == 0) break;
                            if (x == ((U8_T)1 << unit->mDesc.mAddressSize * 8) - 1) {
                                base = (ContextAddress)y;
                            }
                            else if (y > x) {
                                ELF_Section * sec = unit->mTextSection;
                                x = base + x;
                                y = base + y;
                                if (sec_x != NULL) sec = sec_x;
                                else if (sec_y != NULL) sec = sec_y;
                                add_addr_range(sec, unit, (ContextAddress)x, (ContextAddress)(y - x));
                            }
                        }
                        dio_ExitSection();
                    }
                }
                else if (info->u.mCode.mHighPC.mAddr > base) {
                    add_addr_range(unit->mTextSection, unit, base, info->u.mCode.mHighPC.mAddr - base);
                }
            }
            info = info->mSibling;
        }
    }
    if (sCache->mAddrRangesCnt > 1) {
        qsort(sCache->mAddrRanges, sCache->mAddrRangesCnt, sizeof(UnitAddressRange), addr_ranges_comparator);
    }
}

static void add_pub_name(PubNamesTable * tbl, ObjectInfo * obj) {
    PubNamesInfo * info = NULL;
    unsigned h = calc_symbol_name_hash(obj->mName) % tbl->mHashSize;
    if (tbl->mCnt >= tbl->mMax) {
        tbl->mMax = tbl->mMax * 3 / 2;
        tbl->mNext = (PubNamesInfo *)loc_realloc(tbl->mNext, sizeof(PubNamesInfo) * tbl->mMax);
    }
    info = tbl->mNext + tbl->mCnt;
    info->mObject = obj;
    info->mNext = tbl->mHash[h];
    tbl->mHash[h] = tbl->mCnt++;
    obj->mFlags |= DOIF_pub_mark;
}

static void load_pub_names(ELF_Section * debug_info, ELF_Section * pub_names) {
    PubNamesTable * tbl = &sCache->mPubNames;
    dio_EnterSection(NULL, pub_names, 0);
    while (dio_GetPos() < pub_names->size) {
        int dwarf64 = 0;
        U8_T size = dio_ReadU4();
        U8_T next = 0;
        if (size == 0xffffffffu) {
            dwarf64 = 1;
            size = dio_ReadU8();
        }
        next = dio_GetPos() + size;
        if (dio_ReadU2() == 2) {
            ELF_Section * unit_sect = NULL;
            U8_T unit_addr = dio_ReadAddressX(&unit_sect, dwarf64 ? 8 : 4);
            U8_T unit_offs = unit_sect == NULL ? unit_addr : unit_addr - unit_sect->addr;
            U8_T unit_size = dwarf64 ? dio_ReadU8() : (U8_T)dio_ReadU4();
            if (unit_offs + unit_size > debug_info->size) str_fmt_exception(ERR_INV_DWARF,
                "Invalid unit size in %s section", pub_names->name);
            for (;;) {
                char * name = NULL;
                ObjectInfo * info = NULL;
                U8_T obj_offs = dwarf64 ? dio_ReadU8() : (U8_T)dio_ReadU4();
                if (obj_offs == 0) break;
                if (obj_offs >= unit_size) str_fmt_exception(ERR_INV_DWARF,
                    "Invalid object offset in %s section", pub_names->name);
                name = dio_ReadString();
                info = find_loaded_object(sCache, (ContextAddress)(debug_info->addr + unit_offs + obj_offs));
                if (info == NULL) continue;
                if (info->mName == NULL) continue;
                if (info->mFlags & DOIF_pub_mark) continue;
                if (strcmp(info->mName, name) != 0) continue;
                add_pub_name(tbl, info);
            }
        }
        assert(next >= dio_GetPos());
        dio_SetPos(next);
    }
    dio_ExitSection();
}

static void create_pub_names(ELF_Section * debug_info) {
    ObjectInfo * unit = sCache->mCompUnits;
    PubNamesTable * tbl = &sCache->mPubNames;
    while (unit != NULL) {
        ObjectInfo * obj = get_dwarf_children(unit);
        while (obj != NULL) {
            if ((obj->mFlags & DOIF_pub_mark) == 0 && obj->mDefinition == NULL && obj->mName != NULL) {
                add_pub_name(tbl, obj);
            }
            obj = obj->mSibling;
        }
        if ((unit->mFlags & DOIF_pub_mark) == 0 && unit->mName != NULL) {
            add_pub_name(tbl, unit);
        }
        unit = unit->mSibling;
    }
}

static void allocate_obj_hash(void) {
    unsigned idx;
    U8_T size = 0;
    ELF_File * file = sCache->mFile;
    for (idx = 1; idx < file->section_cnt; idx++) {
        ELF_Section * sec = file->sections + idx;
        if (sec->name == NULL) continue;
        if (strcmp(sec->name, ".debug") == 0 || strcmp(sec->name, ".debug_info") == 0) {
            size += sec->size;
        }
    }
    sCache->mObjectHashSize = (unsigned)(size / 53);
    if (sCache->mObjectHashSize < 251) sCache->mObjectHashSize = 251;
    sCache->mObjectHash = (ObjectInfo **)loc_alloc_zero(sizeof(ObjectInfo *) * sCache->mObjectHashSize);
}

static int unit_id_comparator(const void * x1, const void * x2) {
    ObjectInfo * u1 = (*(CompUnit **)x1)->mObject;
    ObjectInfo * u2 = (*(CompUnit **)x2)->mObject;
    if (u1->mID < u2->mID) return -1;
    if (u1->mID > u2->mID) return +1;
    return 0;
}

static void load_debug_sections(void) {
    Trap trap;
    unsigned idx;
    ELF_Section * pub_names = NULL;
    ELF_Section * pub_types = NULL;
    ELF_Section * debug_info = NULL;
    FrameInfoIndex * frame_info_d = NULL;
    FrameInfoIndex * frame_info_e = NULL;
    ELF_File * file = sCache->mFile;

    memset(&trap, 0, sizeof(trap));

    for (idx = 1; idx < file->section_cnt; idx++) {
        ELF_Section * sec = file->sections + idx;
        if (sec->size == 0) continue;
        if (sec->name == NULL) continue;
        if (sec->type == SHT_NOBITS) continue;
        if (strcmp(sec->name, ".debug") == 0 || strcmp(sec->name, ".debug_info") == 0) {
            debug_info = sec;
            sObjRefsCnt = 0;
            sDebugSection = sec;
            sParentObject = NULL;
            sPrevSibling = NULL;
            dio_EnterSection(NULL, sec, 0);
            if (set_trap(&trap)) {
                while (dio_GetPos() < sec->size) {
                    dio_ReadUnit(&sUnitDesc, read_object_info);
                }
                clear_trap(&trap);
            }
            dio_ExitSection();
            sDebugSection = NULL;
            sParentObject = NULL;
            sPrevSibling = NULL;
            sCompUnit = NULL;
            if (sCache->mCompUnitsCnt > 0) {
                unsigned i = 0;
                ObjectInfo * unit = sCache->mCompUnits;
                sCache->mCompUnitsIndex = (CompUnit **)loc_alloc(sizeof(CompUnit *) * sCache->mCompUnitsCnt);
                while (unit != NULL) {
                    assert(unit->mTag == TAG_compile_unit);
                    sCache->mCompUnitsIndex[i++] = unit->mCompUnit;
                    unit = unit->mSibling;
                }
                assert(sCache->mCompUnitsCnt == i);
                qsort(sCache->mCompUnitsIndex, sCache->mCompUnitsCnt, sizeof(CompUnit *), unit_id_comparator);
            }
            if (trap.error) break;
            read_object_refs();
        }
        else if (strcmp(sec->name, ".line") == 0) {
            sCache->mDebugLineV1 = sec;
        }
        else if (strcmp(sec->name, ".debug_line") == 0) {
            sCache->mDebugLineV2 = sec;
        }
        else if (strcmp(sec->name, ".debug_loc") == 0) {
            sCache->mDebugLoc = sec;
        }
        else if (strcmp(sec->name, ".debug_ranges") == 0) {
            sCache->mDebugRanges = sec;
        }
        else if (strcmp(sec->name, ".debug_frame") == 0) {
            FrameInfoIndex * idx = (FrameInfoIndex *)loc_alloc_zero(sizeof(FrameInfoIndex));
            idx->mSection = sec;
            idx->mNext = frame_info_d;
            frame_info_d = idx;
        }
        else if (strcmp(sec->name, ".eh_frame") == 0) {
            FrameInfoIndex * idx = (FrameInfoIndex *)loc_alloc_zero(sizeof(FrameInfoIndex));
            idx->mSection = sec;
            idx->mNext = frame_info_e;
            frame_info_e = idx;
        }
        else if (strcmp(sec->name, ".debug_pubnames") == 0) {
            pub_names = sec;
        }
        else if (strcmp(sec->name, ".debug_pubtypes") == 0) {
            pub_types = sec;
        }
    }

    while (frame_info_e != NULL) {
        FrameInfoIndex * idx = frame_info_e;
        frame_info_e = idx->mNext;
        idx->mNext = sCache->mFrameInfo;
        sCache->mFrameInfo = idx;
    }
    while (frame_info_d != NULL) {
        FrameInfoIndex * idx = frame_info_d;
        frame_info_d = idx->mNext;
        idx->mNext = sCache->mFrameInfo;
        sCache->mFrameInfo = idx;
    }

    if (debug_info) {
        PubNamesTable * tbl = &sCache->mPubNames;
        tbl->mHashSize = tbl->mMax = (unsigned)(debug_info->size / 151) + 16;
        tbl->mHash = (unsigned *)loc_alloc_zero(sizeof(unsigned) * tbl->mHashSize);
        tbl->mNext = (PubNamesInfo *)loc_alloc(sizeof(PubNamesInfo) * tbl->mMax);
        memset(tbl->mNext + tbl->mCnt++, 0, sizeof(PubNamesInfo));
        if (pub_names) load_pub_names(debug_info, pub_names);
        if (pub_types) load_pub_names(debug_info, pub_types);
        create_pub_names(debug_info);
    }

    if (trap.error) exception(trap.error);
}

#if ENABLE_DWARF_LAZY_LOAD
ObjectInfo * get_dwarf_children(ObjectInfo * obj) {
    Trap trap;
    if (obj->mFlags & DOIF_children_loaded) return obj->mChildren;
    sObjRefsCnt = 0;
    sCompUnit = obj->mCompUnit;
    sUnitDesc = sCompUnit->mDesc;
    sDebugSection = sCompUnit->mDesc.mSection;
    sCache = (DWARFCache *)sCompUnit->mFile->dwarf_dt_cache;
    dio_EnterSection(&sCompUnit->mDesc, sDebugSection, obj->mID - sDebugSection->addr);
    if (set_trap(&trap)) {
        U8_T end_pos = sCompUnit->mDesc.mUnitOffs + sCompUnit->mDesc.mUnitSize;
        if (obj->mSibling != NULL) end_pos = obj->mSibling->mID - sDebugSection->addr;
        dio_ReadEntry(NULL, ~(U2_T)0u);
        sParentObject = obj;
        sPrevSibling = NULL;
        while (dio_GetPos() < end_pos) {
            if (!dio_ReadEntry(read_object_info, 0)) break;
        }
        obj->mFlags |= DOIF_children_loaded;
        clear_trap(&trap);
    }
    else {
        /* TODO: dispose obj->mChildren */
        obj->mChildren = NULL;
    }
    dio_ExitSection();
    sDebugSection = NULL;
    sParentObject = NULL;
    sPrevSibling = NULL;
    sCompUnit = NULL;
    if (trap.error) exception(trap.error);
    read_object_refs();
    assert(obj->mFlags & DOIF_children_loaded);
    return obj->mChildren;
}

ObjectInfo * get_dwarf_parent(ObjectInfo * obj) {
    ObjectInfo * x;
    if (obj->mParent != NULL) return obj->mParent;
    if (obj->mTag == TAG_compile_unit) return NULL;
    x = get_dwarf_children(obj->mCompUnit->mObject);
    while (x != NULL && x->mID < obj->mID) {
        if (x->mSibling == NULL || x->mSibling->mID > obj->mID) {
            x = get_dwarf_children(x);
        }
        else {
            x = x->mSibling;
        }
    }
    return obj->mParent;
}
#endif

static U2_T gop_gAttr = 0;
static U2_T gop_gForm = 0;
static U8_T gop_gFormData = 0;
static size_t gop_gFormDataSize = 0;
static void * gop_gFormDataAddr = NULL;
static ELF_Section * gop_gFormSection = NULL;
static U8_T gop_gSpecification = 0;
static U8_T gop_gAbstractOrigin = 0;
static U8_T gop_gExtension = 0;

static void get_object_property_callback(U2_T Tag, U2_T Attr, U2_T Form) {
    if (Attr == AT_specification_v2) gop_gSpecification = dio_gFormData;
    if (Attr == AT_abstract_origin) gop_gAbstractOrigin = dio_gFormData;
    if (Attr == AT_extension) gop_gExtension = dio_gFormData;
    if (Attr != gop_gAttr) return;
    gop_gForm = Form;
    gop_gFormData = dio_gFormData;
    gop_gFormDataSize = dio_gFormDataSize;
    gop_gFormDataAddr = dio_gFormDataAddr;
    gop_gFormSection = dio_gFormSection;
}

U8_T get_numeric_property_value(PropertyValue * Value) {
    U8_T Res = 0;

    if (Value->mPieces != NULL) {
        str_exception(ERR_INV_DWARF, "Constant DWARF attribute value expected");
    }
    else if (Value->mAddr != NULL) {
        size_t i;
        if (Value->mSize > 8) str_exception(ERR_INV_DWARF, "Invalid size of DWARF attribute value");
        for (i = 0; i < Value->mSize; i++) {
            Res = (Res << 8) | Value->mAddr[Value->mBigEndian ? i : Value->mSize - i - 1];
        }
    }
    else {
        Res = Value->mValue;
    }
    return Res;
}

void read_dwarf_object_property(Context * Ctx, int Frame, ObjectInfo * Obj, U2_T Attr, PropertyValue * Value) {

    memset(Value, 0, sizeof(PropertyValue));
    Value->mContext = Ctx;
    Value->mFrame = Frame;
    Value->mObject = Obj;
    Value->mAttr = Attr;
    Value->mBigEndian = Obj->mCompUnit->mFile->big_endian;

    if (Obj->mTag >= TAG_fund_type && Obj->mTag < TAG_fund_type + 0x100) {
        /* Virtual DWARF object that is created by the DWARF reader. It has no properties. */
        if (Obj->mTag == TAG_fund_type) {
            if (Attr == AT_byte_size) {
                Value->mValue = get_fund_type_size(Obj->mCompUnit, Obj->u.mFundType);
                return;
            }
        }
        else if (Obj->mTag == TAG_index_range) {
            if (Attr == AT_lower_bound) {
                switch (Obj->u.mRange.mFmt) {
                case FMT_FT_C_C:
                case FMT_FT_C_X:
                case FMT_UT_C_C:
                case FMT_UT_C_X:
                    Value->mValue = Obj->u.mRange.mLow.mValue;
                    return;
                case FMT_FT_X_C:
                case FMT_FT_X_X:
                case FMT_UT_X_C:
                case FMT_UT_X_X:
                    Value->mForm = FORM_BLOCK2;
                    Value->mAddr = Obj->u.mRange.mLow.mExpr.mAddr;
                    Value->mSize = Obj->u.mRange.mLow.mExpr.mSize;
                    return;
                }
            }
            if (Attr == AT_upper_bound) {
                switch (Obj->u.mRange.mFmt) {
                case FMT_FT_C_C:
                case FMT_FT_X_C:
                case FMT_UT_C_C:
                case FMT_UT_X_C:
                    Value->mValue = Obj->u.mRange.mHigh.mValue;
                    return;
                case FMT_FT_C_X:
                case FMT_FT_X_X:
                case FMT_UT_C_X:
                case FMT_UT_X_X:
                    Value->mForm = FORM_BLOCK2;
                    Value->mAddr = Obj->u.mRange.mHigh.mExpr.mAddr;
                    Value->mSize = Obj->u.mRange.mHigh.mExpr.mSize;
                    return;
                }
            }
        }
        else if (Obj->mTag == TAG_mod_pointer || Obj->mTag == TAG_mod_reference) {
            if (Attr == AT_byte_size) {
                Value->mValue = Obj->mCompUnit->mDesc.mAddressSize;
                return;
            }
        }
        exception(ERR_SYM_NOT_FOUND);
    }

    sCompUnit = Obj->mCompUnit;
    sUnitDesc = sCompUnit->mDesc;
    sDebugSection = sCompUnit->mDesc.mSection;
    sCache = (DWARFCache *)sCompUnit->mFile->dwarf_dt_cache;
    dio_EnterSection(&sCompUnit->mDesc, sDebugSection, Obj->mID - sDebugSection->addr);
    for (;;) {
        if (sUnitDesc.mVersion == 1 && Attr == AT_data_member_location) {
            gop_gAttr = AT_location;
        }
        else {
            gop_gAttr = Attr;
        }
        gop_gForm = 0;
        gop_gSpecification = 0;
        gop_gAbstractOrigin = 0;
        gop_gExtension = 0;
        dio_ReadEntry(get_object_property_callback, gop_gAttr);
        dio_ExitSection();
        if (gop_gForm != 0) break;
        if (gop_gSpecification != 0) dio_EnterSection(&sCompUnit->mDesc, sDebugSection, gop_gSpecification - sDebugSection->addr);
        else if (gop_gAbstractOrigin != 0) dio_EnterSection(&sCompUnit->mDesc, sDebugSection, gop_gAbstractOrigin - sDebugSection->addr);
        else if (gop_gExtension != 0) dio_EnterSection(&sCompUnit->mDesc, sDebugSection, gop_gExtension - sDebugSection->addr);
        else break;
    }

    switch (Value->mForm = gop_gForm) {
    case FORM_REF       :
    case FORM_REF_ADDR  :
    case FORM_REF1      :
    case FORM_REF2      :
    case FORM_REF4      :
    case FORM_REF8      :
    case FORM_REF_UDATA :
        switch (Attr) {
        case AT_import:
        case AT_specification_v2:
        case AT_abstract_origin:
        case AT_containing_type:
            Value->mValue = gop_gFormData;
            break;
        default:
            {
                PropertyValue ValueAddr;
                ObjectInfo * RefObj = find_object(sCache, (ContextAddress)gop_gFormData);

                if (RefObj == NULL) exception(ERR_INV_DWARF);
                read_and_evaluate_dwarf_object_property(Ctx, Frame, RefObj, AT_location, &ValueAddr);
                if (ValueAddr.mPieceCnt == 1 && ValueAddr.mPieces[0].reg != NULL && ValueAddr.mPieces[0].bit_size == 0) {
                    static U1_T Buf[8];
                    StackFrame * Frame = NULL;
                    RegisterDefinition * Register = ValueAddr.mPieces[0].reg;
                    if (get_frame_info(ValueAddr.mContext, ValueAddr.mFrame, &Frame) < 0) exception(errno);
                    if (read_reg_bytes(Frame, Register, 0, Register->size, Buf) < 0) exception(errno);
                    Value->mAddr = Buf;
                    Value->mSize = ValueAddr.mSize;
                    Value->mBigEndian = ValueAddr.mBigEndian;
                }
                else {
                    static U1_T Buf[8];
                    PropertyValue ValueSize;
                    size_t Size;

                    dwarf_expression_obj_addr = get_numeric_property_value(&ValueAddr);
                    read_and_evaluate_dwarf_object_property(Ctx, Frame, RefObj, AT_byte_size, &ValueSize);
                    Size = (size_t)get_numeric_property_value(&ValueSize);
                    if (Size < 1 || Size > sizeof(Buf)) exception(ERR_INV_DATA_TYPE);
                    if (context_read_mem(Ctx, (ContextAddress)dwarf_expression_obj_addr, Buf, Size) < 0) exception(errno);
                    Value->mAddr = Buf;
                    Value->mSize = Size;
                }
            }
            break;
        }
        break;
    case FORM_DATA1     :
    case FORM_DATA2     :
    case FORM_DATA4     :
    case FORM_DATA8     :
    case FORM_FLAG      :
    case FORM_BLOCK1    :
    case FORM_BLOCK2    :
    case FORM_BLOCK4    :
    case FORM_BLOCK     :
    case FORM_STRP      :
    case FORM_SEC_OFFSET:
    case FORM_EXPRLOC   :
    case FORM_REF_SIG8  :
        Value->mAddr = (U1_T *)gop_gFormDataAddr;
        Value->mSize = gop_gFormDataSize;
        break;
    case FORM_SDATA     :
    case FORM_UDATA     :
        Value->mValue = gop_gFormData;
        break;
    case FORM_ADDR      :
        Value->mValue = elf_map_to_run_time_address(Ctx, Obj->mCompUnit->mFile, gop_gFormSection, (ContextAddress)gop_gFormData);
        if (errno) str_exception(errno, "Cannot get object run-time address");
        break;
    default:
        if (Attr == AT_data_member_location && Obj->mTag == TAG_member && Obj->mParent->mTag == TAG_union_type) {
            Value->mForm = FORM_UDATA;
            Value->mValue = 0;
            break;
        }
        if (Attr == AT_byte_size) {
            if (Obj->mTag == TAG_pointer_type || Obj->mTag == TAG_reference_type || Obj->mTag == TAG_mod_pointer || Obj->mTag == TAG_mod_reference) {
                Value->mForm = FORM_UDATA;
                Value->mValue = sCompUnit->mDesc.mAddressSize;
                break;
            }
            if (Obj->mTag == TAG_ptr_to_member_type) {
                Value->mForm = FORM_UDATA;
                Value->mValue = sCompUnit->mDesc.mAddressSize;
                break;
            }
            if (Obj->mTag == TAG_structure_type || Obj->mTag == TAG_class_type || Obj->mTag == TAG_union_type) {
                /* It is OK to return size 0 if the structure has no data members */
                int OK = 1;
                ObjectInfo * c = get_dwarf_children(Obj);
                while (OK && c != NULL) {
                    ObjectInfo * d = c;
                    while (d->mTag == TAG_imported_declaration) {
                        PropertyValue v;
                        read_and_evaluate_dwarf_object_property(Ctx, Frame, d, AT_import, &v);
                        d = find_object(
                            (DWARFCache *)Obj->mCompUnit->mFile->dwarf_dt_cache,
                            (ContextAddress)get_numeric_property_value(&v));
                        if (d == NULL) break;
                    }
                    if (d == NULL) {
                        OK = 0;
                    }
                    else {
                        switch (d->mTag) {
                        case TAG_typedef:
                        case TAG_subprogram:
                        case TAG_template_type_param:
                        case TAG_class_type:
                        case TAG_structure_type:
                        case TAG_union_type:
                        case TAG_enumeration_type:
                            break;
                        case TAG_member:
                            if (d->mFlags & DOIF_external) break;
                            OK = 0;
                            break;
                        default:
                            OK = 0;
                        }
                    }
                    c = c->mSibling;
                }
                if (OK) {
                    Value->mForm = FORM_UDATA;
                    Value->mAddr = 0;
                    Value->mValue = 0;
                    break;
                }
            }
        }
        exception(ERR_SYM_NOT_FOUND);
    }

    sCache = NULL;
    sCompUnit = NULL;
    sDebugSection = NULL;
}

void read_and_evaluate_dwarf_object_property(Context * Ctx, int Frame, ObjectInfo * Obj, U2_T Attr, PropertyValue * Value) {
    read_dwarf_object_property(Ctx, Frame, Obj, Attr, Value);
    assert(Value->mContext == Ctx);
    assert(Value->mFrame == Frame);
    assert(Value->mObject == Obj);
    assert(Value->mAttr == Attr);
    if (Value->mForm == FORM_EXPRLOC) {
        dwarf_evaluate_expression(Value);
    }
    else if (Attr == AT_data_member_location) {
        switch (Value->mForm) {
        case FORM_DATA1     :
        case FORM_DATA2     :
        case FORM_DATA4     :
        case FORM_DATA8     :
        case FORM_SDATA     :
        case FORM_UDATA     :
            Value->mValue = dwarf_expression_obj_addr + get_numeric_property_value(Value);
            Value->mForm = FORM_UDATA;
            Value->mAddr = NULL;
            Value->mSize = 0;
            break;
        case FORM_BLOCK1    :
        case FORM_BLOCK2    :
        case FORM_BLOCK4    :
        case FORM_BLOCK     :
            dwarf_evaluate_expression(Value);
            break;
        }
    }
    else if (Attr == AT_location || Attr == AT_string_length || Attr == AT_frame_base || Attr == AT_use_location) {
        switch (Value->mForm) {
        case FORM_DATA4     :
        case FORM_DATA8     :
        case FORM_BLOCK1    :
        case FORM_BLOCK2    :
        case FORM_BLOCK4    :
        case FORM_BLOCK     :
        case FORM_SEC_OFFSET:
            dwarf_evaluate_expression(Value);
            break;
        }
    }
    else if (Attr == AT_count || Attr == AT_byte_size || Attr == AT_lower_bound || Attr == AT_upper_bound) {
        switch (Value->mForm) {
        case FORM_BLOCK1    :
        case FORM_BLOCK2    :
        case FORM_BLOCK4    :
        case FORM_BLOCK     :
            dwarf_evaluate_expression(Value);
            break;
        }
    }
}

static void free_unit_cache(CompUnit * Unit) {
    Unit->mFilesCnt = 0;
    Unit->mFilesMax = 0;
    loc_free(Unit->mFiles);
    Unit->mFiles = NULL;

    Unit->mDirsCnt = 0;
    Unit->mDirsMax = 0;
    loc_free(Unit->mDirs);
    Unit->mDirs = NULL;

    while (Unit->mStatesCnt > 0) {
        loc_free(Unit->mStates[--Unit->mStatesCnt].mFileName);
    }
    loc_free(Unit->mStates);
    loc_free(Unit->mStatesIndex);
    Unit->mStates = NULL;
    Unit->mStatesMax = 0;
    Unit->mStatesIndex = NULL;
}

static void free_dwarf_cache(ELF_File * file) {
    DWARFCache * Cache = (DWARFCache *)file->dwarf_dt_cache;
    if (Cache != NULL) {
        assert(Cache->magic == DWARF_CACHE_MAGIC);
        Cache->magic = 0;
        loc_free(Cache->mCompUnitsIndex);
        while (Cache->mCompUnits != NULL) {
            CompUnit * Unit = Cache->mCompUnits->mCompUnit;
            Cache->mCompUnits = Cache->mCompUnits->mSibling;
            free_unit_cache(Unit);
            loc_free(Unit);
        }
        while (Cache->mObjectList != NULL) {
            ObjectArray * Buf = Cache->mObjectList;
            Cache->mObjectList = Buf->mNext;
            loc_free(Buf);
        }
        while (Cache->mFrameInfo != NULL) {
            FrameInfoIndex * idx = Cache->mFrameInfo;
            Cache->mFrameInfo = idx->mNext;
            loc_free(idx->mFrameInfoRanges);
            loc_free(idx);
        }
        loc_free(Cache->mObjectHash);
        loc_free(Cache->mAddrRanges);
        loc_free(Cache->mPubNames.mHash);
        loc_free(Cache->mPubNames.mNext);
        loc_free(Cache->mFileInfoHash);
        loc_free(Cache);
        file->dwarf_dt_cache = NULL;
    }
}

DWARFCache * get_dwarf_cache(ELF_File * file) {
    DWARFCache * Cache = (DWARFCache *)file->dwarf_dt_cache;
    if (Cache == NULL) {
        Trap trap;
        if (!sCloseListenerOK) {
            elf_add_close_listener(free_dwarf_cache);
            sCloseListenerOK = 1;
        }
        sCache = Cache = (DWARFCache *)(file->dwarf_dt_cache = loc_alloc_zero(sizeof(DWARFCache)));
        sCache->magic = DWARF_CACHE_MAGIC;
        sCache->mFile = file;
        sCache->mObjectArrayPos = OBJECT_ARRAY_SIZE;
        allocate_obj_hash();
        if (set_trap(&trap)) {
            dio_LoadAbbrevTable(file);
            load_debug_sections();
            load_addr_ranges();
            clear_trap(&trap);
        }
        else {
            sCache->mErrorReport = get_error_report(trap.error);
        }
        sCache = NULL;
    }
    if (Cache->mErrorReport) exception(set_error_report_errno(Cache->mErrorReport));
    return Cache;
}

static void add_dir(CompUnit * Unit, char * Name) {
    if (Unit->mDirsCnt >= Unit->mDirsMax) {
        Unit->mDirsMax = Unit->mDirsMax == 0 ? 16 : Unit->mDirsMax * 2;
        Unit->mDirs = (char **)loc_realloc(Unit->mDirs, sizeof(char *) * Unit->mDirsMax);
    }
    Unit->mDirs[Unit->mDirsCnt++] = Name;
}

static void add_file(CompUnit * Unit, FileInfo * file) {
    file->mNameHash = calc_file_name_hash(file->mName);
    if (Unit->mFilesCnt >= Unit->mFilesMax) {
        Unit->mFilesMax = Unit->mFilesMax == 0 ? 16 : Unit->mFilesMax * 2;
        Unit->mFiles = (FileInfo *)loc_realloc(Unit->mFiles, sizeof(FileInfo) * Unit->mFilesMax);
    }
    if (file->mDir == NULL) file->mDir = Unit->mDir;
    Unit->mFiles[Unit->mFilesCnt++] = *file;
}

static void add_state(CompUnit * Unit, LineNumbersState * state) {
    if (state->mFile >= Unit->mFilesCnt) {
        /* Workaround: Diab compiler generates invalid file indices for an empty compilation unit */
        return;
    }
    if (Unit->mFiles[state->mFile].mAreaCnt++ == 0) {
        /* Workaround: compilers don't produce mapping for first lines in a source file.
         * Such mapping is needed, for example, for re-positioning of source line breakpoints.
         * We add artificial entry for that.
         */
        LineNumbersState s;
        memset(&s, 0, sizeof(s));
        s.mLine = 1;
        s.mFile = state->mFile;
        s.mSection = state->mSection;
        s.mAddress = state->mAddress;
        add_state(Unit, &s);
    }
    if (Unit->mStatesCnt >= Unit->mStatesMax) {
        Unit->mStatesMax = Unit->mStatesMax == 0 ? 128 : Unit->mStatesMax * 2;
        Unit->mStates = (LineNumbersState *)loc_realloc(Unit->mStates, sizeof(LineNumbersState) * Unit->mStatesMax);
    }
    Unit->mStates[Unit->mStatesCnt++] = *state;
}

static int state_address_comparator(const void * x1, const void * x2) {
    LineNumbersState * s1 = (LineNumbersState *)x1;
    LineNumbersState * s2 = (LineNumbersState *)x2;
    if (s1->mSection < s2->mSection) return -1;
    if (s1->mSection > s2->mSection) return +1;
    if (s1->mAddress < s2->mAddress) return -1;
    if (s1->mAddress > s2->mAddress) return +1;
    if (s1->mFile < s2->mFile) return -1;
    if (s1->mFile > s2->mFile) return +1;
    if (s1->mLine < s2->mLine) return -1;
    if (s1->mLine > s2->mLine) return +1;
    if (s1->mColumn < s2->mColumn) return -1;
    if (s1->mColumn > s2->mColumn) return +1;
    return 0;
}

static int state_text_pos_comparator(const void * x1, const void * x2) {
    LineNumbersState * s1 = *(LineNumbersState **)x1;
    LineNumbersState * s2 = *(LineNumbersState **)x2;
    if (s1->mFile < s2->mFile) return -1;
    if (s1->mFile > s2->mFile) return +1;
    if (s1->mLine < s2->mLine) return -1;
    if (s1->mLine > s2->mLine) return +1;
    if (s1->mColumn < s2->mColumn) return -1;
    if (s1->mColumn > s2->mColumn) return +1;
    if (s1->mSection < s2->mSection) return -1;
    if (s1->mSection > s2->mSection) return +1;
    if (s1->mAddress < s2->mAddress) return -1;
    if (s1->mAddress > s2->mAddress) return +1;
    return 0;
}

static void compute_reverse_lookup_indices(DWARFCache * Cache, CompUnit * Unit) {
    U4_T i;
    qsort(Unit->mStates, Unit->mStatesCnt, sizeof(LineNumbersState), state_address_comparator);
    Unit->mStatesIndex = (LineNumbersState **)loc_alloc(sizeof(LineNumbersState *) * Unit->mStatesCnt);
    for (i = 0; i < Unit->mStatesCnt; i++) {
        LineNumbersState * s1 = Unit->mStates + i;
        while (i + 1 < Unit->mStatesCnt) {
            LineNumbersState * s2 = s1 + 1;
            if (s1->mFile != s2->mFile ||
                s1->mLine != s2->mLine || s1->mColumn != s2->mColumn ||
                s1->mFlags != s2->mFlags || s1->mISA != s2->mISA ||
                s1->mOpIndex != s2->mOpIndex || s1->mDiscriminator != s2->mDiscriminator) break;
            memmove(s2, s2 + 1, sizeof(LineNumbersState) * (Unit->mStatesCnt - i - 2));
            Unit->mStatesCnt--;
        }
        Unit->mStatesIndex[i] = s1;
    }
    qsort(Unit->mStatesIndex, Unit->mStatesCnt, sizeof(LineNumbersState *), state_text_pos_comparator);
    for (i = 0; i < Unit->mStatesCnt; i++) Unit->mStatesIndex[i]->mStatesIndexPos = i;
    if (Cache->mFileInfoHash == NULL) {
        Cache->mFileInfoHashSize = 251;
        Cache->mFileInfoHash = (FileInfo **)loc_alloc_zero(sizeof(FileInfo *) * Cache->mFileInfoHashSize);
    }
    for (i = 0; i < Unit->mFilesCnt; i++) {
        FileInfo * File = Unit->mFiles + i;
        unsigned h = File->mNameHash % Cache->mFileInfoHashSize;
        File->mCompUnit = Unit;
        File->mNextInHash = Cache->mFileInfoHash[h];
        Cache->mFileInfoHash[h] = File;
    }
}

static void load_line_numbers_v1(CompUnit * Unit, U4_T unit_size) {
    LineNumbersState state;
    ELF_Section * sec = NULL;
    ContextAddress addr = 0;
    U4_T line = 0;

    memset(&state, 0, sizeof(state));
    addr = (ContextAddress)dio_ReadAddress(&sec);
    if (sec != NULL) state.mSection = sec->index;
    while (dio_GetPos() < Unit->mLineInfoOffs + unit_size) {
        state.mLine = dio_ReadU4();
        state.mColumn = dio_ReadU2();
        if (state.mColumn == 0xffffu) state.mColumn = 0;
        state.mAddress = addr + dio_ReadU4();
        if (state.mLine == 0) {
            state.mLine = line + 1;
            state.mColumn = 0;
        }
        add_state(Unit, &state);
        line = state.mLine;
    }
}

static void load_line_numbers_v2(CompUnit * Unit, U8_T unit_size, int dwarf64) {
    U2_T version = 0;
    U8_T header_pos = 0;
    U1_T opcode_base = 0;
    U1_T opcode_size[256];
    U8_T header_size = 0;
    U1_T min_instruction_length = 0;
    U1_T max_ops_per_instruction = 1;
    U1_T is_stmt_default = 0;
    I1_T line_base = 0;
    U1_T line_range = 0;
    LineNumbersState state;

    version = dio_ReadU2();
    if (version < 2 || version > 4) str_exception(ERR_INV_DWARF, "Invalid line number info version");
    header_size = dwarf64 ? dio_ReadU8() : (U8_T)dio_ReadU4();
    header_pos = dio_GetPos();
    min_instruction_length = dio_ReadU1();
    if (version >= 4) max_ops_per_instruction = dio_ReadU1();
    is_stmt_default = dio_ReadU1() != 0;
    line_base = (I1_T)dio_ReadU1();
    line_range = dio_ReadU1();
    opcode_base = dio_ReadU1();
    memset(opcode_size, 0, sizeof(opcode_size));
    dio_Read(opcode_size + 1, opcode_base - 1);

    /* Read directory names */
    for (;;) {
        char * Name = dio_ReadString();
        if (Name == NULL) break;
        add_dir(Unit, Name);
    }

    /* Read source files info */
    for (;;) {
        U4_T dir = 0;
        FileInfo file;
        memset(&file, 0, sizeof(file));
        file.mName = dio_ReadString();
        if (file.mName == NULL) break;
        dir = dio_ReadULEB128();
        if (dir > 0 && dir <= Unit->mDirsCnt) file.mDir = Unit->mDirs[dir - 1];
        file.mModTime = dio_ReadULEB128();
        file.mSize = dio_ReadULEB128();
        add_file(Unit, &file);
    }

    /* Run the program */
    if (header_pos + header_size != dio_GetPos())
        str_exception(ERR_INV_DWARF, "Invalid line info header");
    memset(&state, 0, sizeof(state));
    state.mFile = 1;
    state.mLine = 1;
    if (is_stmt_default) state.mFlags |= LINE_IsStmt;
    while (dio_GetPos() < Unit->mLineInfoOffs + unit_size) {
        U1_T opcode = dio_ReadU1();
        if (opcode >= opcode_base) {
            unsigned op_advance = (opcode - opcode_base) / line_range;
            state.mLine += (U4_T)((int)((opcode - opcode_base) % line_range) + line_base);
            state.mAddress += (state.mOpIndex + op_advance) / max_ops_per_instruction * min_instruction_length;
            state.mOpIndex = (state.mOpIndex + op_advance) % max_ops_per_instruction;
            add_state(Unit, &state);
            state.mFlags &= ~(LINE_BasicBlock | LINE_PrologueEnd | LINE_EpilogueBegin);
            state.mDiscriminator = 0;
        }
        else if (opcode == 0) {
            ELF_Section * sec = NULL;
            U4_T op_size = dio_ReadULEB128();
            U8_T op_pos = dio_GetPos();
            switch (dio_ReadU1()) {
            case DW_LNE_define_file: {
                U4_T dir = 0;
                FileInfo file;
                memset(&file, 0, sizeof(file));
                file.mName = dio_ReadString();
                dir = dio_ReadULEB128();
                if (dir > 0 && dir <= Unit->mDirsCnt) file.mDir = Unit->mDirs[dir - 1];
                file.mModTime = dio_ReadULEB128();
                file.mSize = dio_ReadULEB128();
                add_file(Unit, &file);
                break;
            }
            case DW_LNE_end_sequence:
                state.mFlags |= LINE_EndSequence;
                add_state(Unit, &state);
                memset(&state, 0, sizeof(state));
                state.mFile = 1;
                state.mLine = 1;
                if (is_stmt_default) state.mFlags |= LINE_IsStmt;
                else state.mFlags &= ~LINE_IsStmt;
                break;
            case DW_LNE_set_address:
                state.mAddress = (ContextAddress)dio_ReadAddress(&sec);
                state.mSection = sec != NULL ? sec->index : 0;
                break;
            case DW_LNE_set_discriminator:
                state.mDiscriminator = (U1_T)dio_ReadULEB128();
                break;
            default:
                dio_Skip(op_size - 1);
                break;
            }
            if (dio_GetPos() != op_pos + op_size)
                str_exception(ERR_INV_DWARF, "Invalid line info op size");
        }
        else {
            switch (opcode) {
            case DW_LNS_copy:
                add_state(Unit, &state);
                state.mFlags &= ~(LINE_BasicBlock | LINE_PrologueEnd | LINE_EpilogueBegin);
                break;
            case DW_LNS_advance_pc:
                state.mAddress += (ContextAddress)(dio_ReadU8LEB128() * min_instruction_length);
                break;
            case DW_LNS_advance_line:
                state.mLine += dio_ReadSLEB128();
                break;
            case DW_LNS_set_file:
                state.mFile = dio_ReadULEB128();
                break;
            case DW_LNS_set_column:
                state.mColumn = (U2_T)dio_ReadULEB128();
                break;
            case DW_LNS_negate_stmt:
                state.mFlags ^= LINE_IsStmt;
                break;
            case DW_LNS_set_basic_block:
                state.mFlags |= LINE_BasicBlock;
                break;
            case DW_LNS_const_add_pc:
                state.mAddress += (255 - opcode_base) / line_range * min_instruction_length;
                break;
            case DW_LNS_fixed_advance_pc:
                state.mAddress += dio_ReadU2();
                break;
            case DW_LNS_set_prologue_end:
                state.mFlags |= LINE_PrologueEnd;
                break;
            case DW_LNS_set_epilogue_begin:
                state.mFlags |= LINE_EpilogueBegin;
                break;
            case DW_LNS_set_isa:
                state.mISA = (U1_T)dio_ReadULEB128();
                break;
            default:
                str_exception(ERR_INV_DWARF, "Invalid line info op code");
                break;
            }
        }
    }
}

void load_line_numbers(CompUnit * Unit) {
    Trap trap;
    DWARFCache * Cache = (DWARFCache *)Unit->mFile->dwarf_dt_cache;
    ELF_Section * LineInfoSection = Unit->mDesc.mVersion <= 1 ? Cache->mDebugLineV1 : Cache->mDebugLineV2;
    if (LineInfoSection == NULL) return;
    if (Unit->mLineInfoLoaded) return;
    if (elf_load(LineInfoSection)) exception(errno);
    dio_EnterSection(&Unit->mDesc, LineInfoSection, Unit->mLineInfoOffs);
    if (set_trap(&trap)) {
        U8_T unit_size = 0;
        FileInfo file;
        memset(&file, 0, sizeof(file));
        file.mDir = Unit->mDir;
        file.mName = Unit->mObject->mName;
        add_file(Unit, &file);
        /* Read header */
        unit_size = dio_ReadU4();
        if (Unit->mDesc.mVersion <= 1) {
            /* DWARF 1.1 */
            load_line_numbers_v1(Unit, (U4_T)unit_size);
        }
        else {
            /* DWARF 2+ */
            int dwarf64 = 0;
            if (unit_size == 0xffffffffu) {
                unit_size = dio_ReadU8();
                unit_size += 12;
                dwarf64 = 1;
            }
            else {
                unit_size += 4;
            }
            load_line_numbers_v2(Unit, unit_size, dwarf64);
        }
        dio_ExitSection();
        compute_reverse_lookup_indices(Cache, Unit);
        Unit->mLineInfoLoaded = 1;
        clear_trap(&trap);
    }
    else {
        dio_ExitSection();
        free_unit_cache(Unit);
        exception(trap.error);
    }
}

UnitAddressRange * find_comp_unit_addr_range(DWARFCache * cache, ELF_Section * section,
                                             ContextAddress addr_min, ContextAddress addr_max) {
    unsigned l = 0;
    unsigned h = cache->mAddrRangesCnt;
    U4_T s = 0;

    if (cache->mAddrRangesRelocatable && section != NULL) {
        if (section->file == cache->mFile) {
            s = section->index;
        }
        else {
            unsigned i;
            assert(get_dwarf_file(section->file) == cache->mFile);
            for (i = 1; i < cache->mFile->section_cnt; i++) {
                ELF_Section * sec = cache->mFile->sections + i;
                if (sec->name == NULL) continue;
                if (strcmp(sec->name, section->name) == 0) {
                    s = i;
                    break;
                }
            }
        }
    }

    while (l < h) {
        unsigned k = (h + l) / 2;
        UnitAddressRange * rk = cache->mAddrRanges + k;
        if (rk->mSection > s) h = k;
        else if (rk->mSection < s) l = k + 1;
        else if (rk->mAddr <= addr_max && rk->mAddr + rk->mSize > addr_min) {
            int first = 1;
            if (k > 0) {
                UnitAddressRange * rp = rk - 1;
                first = rp->mAddr + rp->mSize <= addr_min;
            }
            if (first) return rk;
            h = k;
        }
        else if (rk->mAddr >= addr_min) h = k;
        else l = k + 1;
    }
    return NULL;
}

#endif /* ENABLE_ELF && ENABLE_DebugContext */
