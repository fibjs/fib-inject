/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef LIEF_PE_OLEAUT32_DLL_LOOKUP_H_
#define LIEF_PE_OLEAUT32_DLL_LOOKUP_H_


namespace LIEF {
namespace PE {

const char* oleaut32_dll_lookup(uint32_t i) {
  switch(i) {
  case 0x011e: return "BSTR_UserFree";
  case 0x011c: return "BSTR_UserMarshal";
  case 0x011b: return "BSTR_UserSize";
  case 0x011d: return "BSTR_UserUnmarshal";
  case 0x019e: return "BstrFromVector";
  case 0x00ab: return "ClearCustData";
  case 0x001f: return "CreateDispTypeInfo";
  case 0x00ca: return "CreateErrorInfo";
  case 0x0020: return "CreateStdDispatch";
  case 0x00a0: return "CreateTypeLib";
  case 0x00b4: return "CreateTypeLib2";
  case 0x0092: return "DispCallFunc";
  case 0x001d: return "DispGetIDsOfNames";
  case 0x001c: return "DispGetParam";
  case 0x001e: return "DispInvoke";
  case 0x0090: return "DllCanUnloadNow";
  case 0x0091: return "DllGetClassObject";
  case 0x0097: return "DllRegisterServer";
  case 0x012c: return "DllUnregisterServer";
  case 0x000e: return "DosDateTimeToVariantTime";
  case 0x0023: return "GetActiveObject";
  case 0x014c: return "GetAltMonthNames";
  case 0x00c8: return "GetErrorInfo";
  case 0x0142: return "GetRecordInfoFromGuids";
  case 0x0143: return "GetRecordInfoFromTypeInfo";
  case 0x0146: return "GetVarConversionLocaleSetting";
  case 0x00a5: return "LHashValOfNameSys";
  case 0x00a6: return "LHashValOfNameSysA";
  case 0x0128: return "LPSAFEARRAY_Marshal";
  case 0x0127: return "LPSAFEARRAY_Size";
  case 0x0129: return "LPSAFEARRAY_Unmarshal";
  case 0x0126: return "LPSAFEARRAY_UserFree";
  case 0x0124: return "LPSAFEARRAY_UserMarshal";
  case 0x0123: return "LPSAFEARRAY_UserSize";
  case 0x0125: return "LPSAFEARRAY_UserUnmarshal";
  case 0x00a2: return "LoadRegTypeLib";
  case 0x00a1: return "LoadTypeLib";
  case 0x00b7: return "LoadTypeLibEx";
  case 0x012d: return "OACreateTypeLib2";
  case 0x00aa: return "OaBuildVersion";
  case 0x01a4: return "OleCreateFontIndirect";
  case 0x01a3: return "OleCreatePictureIndirect";
  case 0x01a1: return "OleCreatePropertyFrame";
  case 0x01a0: return "OleCreatePropertyFrameIndirect";
  case 0x019f: return "OleIconToCursor";
  case 0x01a2: return "OleLoadPicture";
  case 0x0191: return "OleLoadPictureEx";
  case 0x01a6: return "OleLoadPictureFile";
  case 0x0192: return "OleLoadPictureFileEx";
  case 0x01a8: return "OleLoadPicturePath";
  case 0x01a7: return "OleSavePictureFile";
  case 0x01a5: return "OleTranslateColor";
  case 0x00a4: return "QueryPathOfRegTypeLib";
  case 0x0021: return "RegisterActiveObject";
  case 0x00a3: return "RegisterTypeLib";
  case 0x01ba: return "RegisterTypeLibForUser";
  case 0x0022: return "RevokeActiveObject";
  case 0x0017: return "SafeArrayAccessData";
  case 0x0025: return "SafeArrayAllocData";
  case 0x0024: return "SafeArrayAllocDescriptor";
  case 0x0029: return "SafeArrayAllocDescriptorEx";
  case 0x001b: return "SafeArrayCopy";
  case 0x019c: return "SafeArrayCopyData";
  case 0x000f: return "SafeArrayCreate";
  case 0x002a: return "SafeArrayCreateEx";
  case 0x019b: return "SafeArrayCreateVector";
  case 0x002b: return "SafeArrayCreateVectorEx";
  case 0x0010: return "SafeArrayDestroy";
  case 0x0027: return "SafeArrayDestroyData";
  case 0x0026: return "SafeArrayDestroyDescriptor";
  case 0x0011: return "SafeArrayGetDim";
  case 0x0019: return "SafeArrayGetElement";
  case 0x0012: return "SafeArrayGetElemsize";
  case 0x0043: return "SafeArrayGetIID";
  case 0x0014: return "SafeArrayGetLBound";
  case 0x002d: return "SafeArrayGetRecordInfo";
  case 0x0013: return "SafeArrayGetUBound";
  case 0x004d: return "SafeArrayGetVartype";
  case 0x0015: return "SafeArrayLock";
  case 0x0094: return "SafeArrayPtrOfIndex";
  case 0x001a: return "SafeArrayPutElement";
  case 0x0028: return "SafeArrayRedim";
  case 0x0039: return "SafeArraySetIID";
  case 0x002c: return "SafeArraySetRecordInfo";
  case 0x0018: return "SafeArrayUnaccessData";
  case 0x0016: return "SafeArrayUnlock";
  case 0x00c9: return "SetErrorInfo";
  case 0x0147: return "SetOaNoCache";
  case 0x0145: return "SetVarConversionLocaleSetting";
  case 0x0002: return "SysAllocString";
  case 0x0096: return "SysAllocStringByteLen";
  case 0x0004: return "SysAllocStringLen";
  case 0x0006: return "SysFreeString";
  case 0x0003: return "SysReAllocString";
  case 0x0005: return "SysReAllocStringLen";
  case 0x0095: return "SysStringByteLen";
  case 0x0007: return "SysStringLen";
  case 0x00b8: return "SystemTimeToVariantTime";
  case 0x00ba: return "UnRegisterTypeLib";
  case 0x01bb: return "UnRegisterTypeLibForUser";
  case 0x0122: return "VARIANT_UserFree";
  case 0x0120: return "VARIANT_UserMarshal";
  case 0x011f: return "VARIANT_UserSize";
  case 0x0121: return "VARIANT_UserUnmarshal";
  case 0x00a8: return "VarAbs";
  case 0x008d: return "VarAdd";
  case 0x008e: return "VarAnd";
  case 0x007c: return "VarBoolFromCy";
  case 0x007b: return "VarBoolFromDate";
  case 0x00ec: return "VarBoolFromDec";
  case 0x007e: return "VarBoolFromDisp";
  case 0x00e9: return "VarBoolFromI1";
  case 0x0077: return "VarBoolFromI2";
  case 0x0078: return "VarBoolFromI4";
  case 0x0172: return "VarBoolFromI8";
  case 0x0079: return "VarBoolFromR4";
  case 0x007a: return "VarBoolFromR8";
  case 0x007d: return "VarBoolFromStr";
  case 0x0076: return "VarBoolFromUI1";
  case 0x00ea: return "VarBoolFromUI2";
  case 0x00eb: return "VarBoolFromUI4";
  case 0x0173: return "VarBoolFromUI8";
  case 0x0139: return "VarBstrCat";
  case 0x013a: return "VarBstrCmp";
  case 0x0074: return "VarBstrFromBool";
  case 0x0071: return "VarBstrFromCy";
  case 0x0072: return "VarBstrFromDate";
  case 0x00e8: return "VarBstrFromDec";
  case 0x0073: return "VarBstrFromDisp";
  case 0x00e5: return "VarBstrFromI1";
  case 0x006d: return "VarBstrFromI2";
  case 0x006e: return "VarBstrFromI4";
  case 0x0170: return "VarBstrFromI8";
  case 0x006f: return "VarBstrFromR4";
  case 0x0070: return "VarBstrFromR8";
  case 0x006c: return "VarBstrFromUI1";
  case 0x00e6: return "VarBstrFromUI2";
  case 0x00e7: return "VarBstrFromUI4";
  case 0x0171: return "VarBstrFromUI8";
  case 0x013e: return "VarCat";
  case 0x00b0: return "VarCmp";
  case 0x0132: return "VarCyAbs";
  case 0x012b: return "VarCyAdd";
  case 0x0137: return "VarCyCmp";
  case 0x0138: return "VarCyCmpR8";
  case 0x0133: return "VarCyFix";
  case 0x006a: return "VarCyFromBool";
  case 0x0067: return "VarCyFromDate";
  case 0x00e4: return "VarCyFromDec";
  case 0x0069: return "VarCyFromDisp";
  case 0x00e1: return "VarCyFromI1";
  case 0x0063: return "VarCyFromI2";
  case 0x0064: return "VarCyFromI4";
  case 0x016e: return "VarCyFromI8";
  case 0x0065: return "VarCyFromR4";
  case 0x0066: return "VarCyFromR8";
  case 0x0068: return "VarCyFromStr";
  case 0x0062: return "VarCyFromUI1";
  case 0x00e2: return "VarCyFromUI2";
  case 0x00e3: return "VarCyFromUI4";
  case 0x016f: return "VarCyFromUI8";
  case 0x0134: return "VarCyInt";
  case 0x012f: return "VarCyMul";
  case 0x0130: return "VarCyMulI4";
  case 0x0149: return "VarCyMulI8";
  case 0x0135: return "VarCyNeg";
  case 0x0136: return "VarCyRound";
  case 0x0131: return "VarCySub";
  case 0x0060: return "VarDateFromBool";
  case 0x005d: return "VarDateFromCy";
  case 0x00e0: return "VarDateFromDec";
  case 0x005f: return "VarDateFromDisp";
  case 0x00dd: return "VarDateFromI1";
  case 0x0059: return "VarDateFromI2";
  case 0x005a: return "VarDateFromI4";
  case 0x016c: return "VarDateFromI8";
  case 0x005b: return "VarDateFromR4";
  case 0x005c: return "VarDateFromR8";
  case 0x005e: return "VarDateFromStr";
  case 0x0058: return "VarDateFromUI1";
  case 0x00de: return "VarDateFromUI2";
  case 0x00df: return "VarDateFromUI4";
  case 0x016d: return "VarDateFromUI8";
  case 0x014a: return "VarDateFromUdate";
  case 0x013f: return "VarDateFromUdateEx";
  case 0x00b6: return "VarDecAbs";
  case 0x00b1: return "VarDecAdd";
  case 0x00cc: return "VarDecCmp";
  case 0x012a: return "VarDecCmpR8";
  case 0x00b2: return "VarDecDiv";
  case 0x00bb: return "VarDecFix";
  case 0x00c7: return "VarDecFromBool";
  case 0x00c4: return "VarDecFromCy";
  case 0x00c3: return "VarDecFromDate";
  case 0x00c6: return "VarDecFromDisp";
  case 0x00f1: return "VarDecFromI1";
  case 0x00bf: return "VarDecFromI2";
  case 0x00c0: return "VarDecFromI4";
  case 0x0176: return "VarDecFromI8";
  case 0x00c1: return "VarDecFromR4";
  case 0x00c2: return "VarDecFromR8";
  case 0x00c5: return "VarDecFromStr";
  case 0x00be: return "VarDecFromUI1";
  case 0x00f2: return "VarDecFromUI2";
  case 0x00f3: return "VarDecFromUI4";
  case 0x0177: return "VarDecFromUI8";
  case 0x00bc: return "VarDecInt";
  case 0x00b3: return "VarDecMul";
  case 0x00bd: return "VarDecNeg";
  case 0x00cb: return "VarDecRound";
  case 0x00b5: return "VarDecSub";
  case 0x008f: return "VarDiv";
  case 0x0098: return "VarEqv";
  case 0x00a9: return "VarFix";
  case 0x0057: return "VarFormat";
  case 0x007f: return "VarFormatCurrency";
  case 0x0061: return "VarFormatDateTime";
  case 0x008b: return "VarFormatFromTokens";
  case 0x006b: return "VarFormatNumber";
  case 0x0075: return "VarFormatPercent";
  case 0x00fd: return "VarI1FromBool";
  case 0x00fa: return "VarI1FromCy";
  case 0x00f9: return "VarI1FromDate";
  case 0x0100: return "VarI1FromDec";
  case 0x00fc: return "VarI1FromDisp";
  case 0x00f5: return "VarI1FromI2";
  case 0x00f6: return "VarI1FromI4";
  case 0x0178: return "VarI1FromI8";
  case 0x00f7: return "VarI1FromR4";
  case 0x00f8: return "VarI1FromR8";
  case 0x00fb: return "VarI1FromStr";
  case 0x00f4: return "VarI1FromUI1";
  case 0x00fe: return "VarI1FromUI2";
  case 0x00ff: return "VarI1FromUI4";
  case 0x0179: return "VarI1FromUI8";
  case 0x0038: return "VarI2FromBool";
  case 0x0034: return "VarI2FromCy";
  case 0x0035: return "VarI2FromDate";
  case 0x00d0: return "VarI2FromDec";
  case 0x0037: return "VarI2FromDisp";
  case 0x00cd: return "VarI2FromI1";
  case 0x0031: return "VarI2FromI4";
  case 0x015a: return "VarI2FromI8";
  case 0x0032: return "VarI2FromR4";
  case 0x0033: return "VarI2FromR8";
  case 0x0036: return "VarI2FromStr";
  case 0x0030: return "VarI2FromUI1";
  case 0x00ce: return "VarI2FromUI2";
  case 0x00cf: return "VarI2FromUI4";
  case 0x015b: return "VarI2FromUI8";
  case 0x0042: return "VarI4FromBool";
  case 0x003e: return "VarI4FromCy";
  case 0x003f: return "VarI4FromDate";
  case 0x00d4: return "VarI4FromDec";
  case 0x0041: return "VarI4FromDisp";
  case 0x00d1: return "VarI4FromI1";
  case 0x003b: return "VarI4FromI2";
  case 0x015c: return "VarI4FromI8";
  case 0x003c: return "VarI4FromR4";
  case 0x003d: return "VarI4FromR8";
  case 0x0040: return "VarI4FromStr";
  case 0x003a: return "VarI4FromUI1";
  case 0x00d2: return "VarI4FromUI2";
  case 0x00d3: return "VarI4FromUI4";
  case 0x015d: return "VarI4FromUI8";
  case 0x0155: return "VarI8FromBool";
  case 0x0151: return "VarI8FromCy";
  case 0x0152: return "VarI8FromDate";
  case 0x0159: return "VarI8FromDec";
  case 0x0154: return "VarI8FromDisp";
  case 0x0156: return "VarI8FromI1";
  case 0x014e: return "VarI8FromI2";
  case 0x014f: return "VarI8FromR4";
  case 0x0150: return "VarI8FromR8";
  case 0x0153: return "VarI8FromStr";
  case 0x014d: return "VarI8FromUI1";
  case 0x0157: return "VarI8FromUI2";
  case 0x0158: return "VarI8FromUI4";
  case 0x01ab: return "VarI8FromUI8";
  case 0x0099: return "VarIdiv";
  case 0x009a: return "VarImp";
  case 0x00ac: return "VarInt";
  case 0x009b: return "VarMod";
  case 0x0081: return "VarMonthName";
  case 0x009c: return "VarMul";
  case 0x00ad: return "VarNeg";
  case 0x00ae: return "VarNot";
  case 0x002f: return "VarNumFromParseNum";
  case 0x009d: return "VarOr";
  case 0x002e: return "VarParseNumFromStr";
  case 0x009e: return "VarPow";
  case 0x013c: return "VarR4CmpR8";
  case 0x004c: return "VarR4FromBool";
  case 0x0048: return "VarR4FromCy";
  case 0x0049: return "VarR4FromDate";
  case 0x00d8: return "VarR4FromDec";
  case 0x004b: return "VarR4FromDisp";
  case 0x00d5: return "VarR4FromI1";
  case 0x0045: return "VarR4FromI2";
  case 0x0046: return "VarR4FromI4";
  case 0x0168: return "VarR4FromI8";
  case 0x0047: return "VarR4FromR8";
  case 0x004a: return "VarR4FromStr";
  case 0x0044: return "VarR4FromUI1";
  case 0x00d6: return "VarR4FromUI2";
  case 0x00d7: return "VarR4FromUI4";
  case 0x0169: return "VarR4FromUI8";
  case 0x0056: return "VarR8FromBool";
  case 0x0052: return "VarR8FromCy";
  case 0x0053: return "VarR8FromDate";
  case 0x00dc: return "VarR8FromDec";
  case 0x0055: return "VarR8FromDisp";
  case 0x00d9: return "VarR8FromI1";
  case 0x004f: return "VarR8FromI2";
  case 0x0050: return "VarR8FromI4";
  case 0x016a: return "VarR8FromI8";
  case 0x0051: return "VarR8FromR4";
  case 0x0054: return "VarR8FromStr";
  case 0x004e: return "VarR8FromUI1";
  case 0x00da: return "VarR8FromUI2";
  case 0x00db: return "VarR8FromUI4";
  case 0x016b: return "VarR8FromUI8";
  case 0x013b: return "VarR8Pow";
  case 0x013d: return "VarR8Round";
  case 0x00af: return "VarRound";
  case 0x009f: return "VarSub";
  case 0x008c: return "VarTokenizeFormatString";
  case 0x008a: return "VarUI1FromBool";
  case 0x0086: return "VarUI1FromCy";
  case 0x0087: return "VarUI1FromDate";
  case 0x00f0: return "VarUI1FromDec";
  case 0x0089: return "VarUI1FromDisp";
  case 0x00ed: return "VarUI1FromI1";
  case 0x0082: return "VarUI1FromI2";
  case 0x0083: return "VarUI1FromI4";
  case 0x0174: return "VarUI1FromI8";
  case 0x0084: return "VarUI1FromR4";
  case 0x0085: return "VarUI1FromR8";
  case 0x0088: return "VarUI1FromStr";
  case 0x00ee: return "VarUI1FromUI2";
  case 0x00ef: return "VarUI1FromUI4";
  case 0x0175: return "VarUI1FromUI8";
  case 0x010a: return "VarUI2FromBool";
  case 0x0107: return "VarUI2FromCy";
  case 0x0106: return "VarUI2FromDate";
  case 0x010d: return "VarUI2FromDec";
  case 0x0109: return "VarUI2FromDisp";
  case 0x010b: return "VarUI2FromI1";
  case 0x0102: return "VarUI2FromI2";
  case 0x0103: return "VarUI2FromI4";
  case 0x017a: return "VarUI2FromI8";
  case 0x0104: return "VarUI2FromR4";
  case 0x0105: return "VarUI2FromR8";
  case 0x0108: return "VarUI2FromStr";
  case 0x0101: return "VarUI2FromUI1";
  case 0x010c: return "VarUI2FromUI4";
  case 0x017b: return "VarUI2FromUI8";
  case 0x0117: return "VarUI4FromBool";
  case 0x0114: return "VarUI4FromCy";
  case 0x0113: return "VarUI4FromDate";
  case 0x011a: return "VarUI4FromDec";
  case 0x0116: return "VarUI4FromDisp";
  case 0x0118: return "VarUI4FromI1";
  case 0x010f: return "VarUI4FromI2";
  case 0x0110: return "VarUI4FromI4";
  case 0x01a9: return "VarUI4FromI8";
  case 0x0111: return "VarUI4FromR4";
  case 0x0112: return "VarUI4FromR8";
  case 0x0115: return "VarUI4FromStr";
  case 0x010e: return "VarUI4FromUI1";
  case 0x0119: return "VarUI4FromUI2";
  case 0x01aa: return "VarUI4FromUI8";
  case 0x01b5: return "VarUI8FromBool";
  case 0x01b1: return "VarUI8FromCy";
  case 0x01b2: return "VarUI8FromDate";
  case 0x01b9: return "VarUI8FromDec";
  case 0x01b4: return "VarUI8FromDisp";
  case 0x01b6: return "VarUI8FromI1";
  case 0x01ae: return "VarUI8FromI2";
  case 0x01ac: return "VarUI8FromI8";
  case 0x01af: return "VarUI8FromR4";
  case 0x01b0: return "VarUI8FromR8";
  case 0x01b3: return "VarUI8FromStr";
  case 0x01ad: return "VarUI8FromUI1";
  case 0x01b7: return "VarUI8FromUI2";
  case 0x01b8: return "VarUI8FromUI4";
  case 0x014b: return "VarUdateFromDate";
  case 0x0080: return "VarWeekdayName";
  case 0x00a7: return "VarXor";
  case 0x000c: return "VariantChangeType";
  case 0x0093: return "VariantChangeTypeEx";
  case 0x0009: return "VariantClear";
  case 0x000a: return "VariantCopy";
  case 0x000b: return "VariantCopyInd";
  case 0x0008: return "VariantInit";
  case 0x000d: return "VariantTimeToDosDateTime";
  case 0x00b9: return "VariantTimeToSystemTime";
  case 0x019d: return "VectorFromBstr";
  }
  return nullptr;
}


}
}

#endif

