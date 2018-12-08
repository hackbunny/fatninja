#include "stdafx.h"

template<class T, class OffT> static __forceinline T RVA(const void * base, OffT offset)
{
	return static_cast<T>(static_cast<const void *>(static_cast<const unsigned char *>(base) + offset));
}

template<class T, class OffT> static __forceinline T RVA(void * base, OffT offset)
{
	return static_cast<T>(static_cast<void *>(static_cast<unsigned char *>(base) + offset));
}

typedef PTHREAD_START_ROUTINE (NTAPI * PStubEntry)(PIMAGE_DOS_HEADER);

PIMAGE_DOS_HEADER bareLoadLibrary(LPCTSTR fileName)
{
	HANDLE hFile = CreateFile
	(
		fileName,
		FILE_READ_DATA,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);

	if(hFile != INVALID_HANDLE_VALUE)
	{
		HANDLE hSection = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);

		if(hSection)
		{
			PTEB pTeb = NtCurrentTeb();
			PVOID save = pTeb->Tib.ArbitraryUserPointer;
			pTeb->Tib.ArbitraryUserPointer = const_cast<LPTSTR>(fileName);

			PVOID pBase = MapViewOfFile(hSection, FILE_MAP_EXECUTE, 0, 0, 0);

			pTeb->Tib.ArbitraryUserPointer = save;

			if(pBase)
			{
				CloseHandle(hSection);
				CloseHandle(hFile);
				return static_cast<PIMAGE_DOS_HEADER>(pBase);
			}

			CloseHandle(hSection);
		}

		CloseHandle(hFile);
	}

	return NULL;
}

void bareFreeLibrary(const void * base)
{
	UnmapViewOfFile(base);
}

static const LPCTSTR directoryNames[] =
{
	TEXT("export"),                // IMAGE_DIRECTORY_ENTRY_EXPORT   
	TEXT("import"),                // IMAGE_DIRECTORY_ENTRY_IMPORT   
	TEXT("resource"),              // IMAGE_DIRECTORY_ENTRY_RESOURCE 
	TEXT("exception"),             // IMAGE_DIRECTORY_ENTRY_EXCEPTION
	TEXT("security"),              // IMAGE_DIRECTORY_ENTRY_SECURITY 
	TEXT("relocation"),            // IMAGE_DIRECTORY_ENTRY_BASERELOC
	TEXT("debug"),	               // IMAGE_DIRECTORY_ENTRY_DEBUG    
	TEXT("architecture-specific"), // IMAGE_DIRECTORY_ENTRY_ARCHITECTURE  
	TEXT("global pointer"),        // IMAGE_DIRECTORY_ENTRY_GLOBALPTR     
	TEXT("TLS"),                   // IMAGE_DIRECTORY_ENTRY_TLS           
	TEXT("load configuration"),    // IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG   
	TEXT("bound imports"),         // IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT  
	TEXT("import address table"),  // IMAGE_DIRECTORY_ENTRY_IAT           
	TEXT("delayed imports"),       // IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT  
	TEXT(".NET"),                  // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
};

BOOL CALLBACK findManifest(HMODULE, LPTSTR lpszType, LONG_PTR)
{
	return lpszType != RT_MANIFEST;
}

bool hasManifest(HMODULE hm)
{
	SetLastError(0);

	BOOL bRet = EnumResourceTypes(hm, findManifest, 0);

	if(!bRet && GetLastError() == 0)
		return true;

	return false;
}

bool validateStub(PIMAGE_DOS_HEADER pStub)
{	
	PIMAGE_NT_HEADERS pNtHeaders = RtlImageNtHeader(pStub);

	if(pNtHeaders == NULL)
	{
		_ftprintf(stderr, _T("%s: the %s isn't a valid PE image\n"), _T("error"), _T("stub"));
		return false;
	}

	if(hasManifest(reinterpret_cast<HMODULE>(pStub)))
	{
		_ftprintf(stderr, _T("%s: the %s contains a %s resource, which is %s\n"), _T("error"), _T("stub"), _T("manifest"), _T("unsupported"));
		return false;
	}

	// true = useless, false = unsupported
	bool uselessOrUnsupported[] =
	{
		true,  // IMAGE_DIRECTORY_ENTRY_EXPORT   
		false, // IMAGE_DIRECTORY_ENTRY_IMPORT   
		true,  // IMAGE_DIRECTORY_ENTRY_RESOURCE 
		false, // IMAGE_DIRECTORY_ENTRY_EXCEPTION // TODO: we could support this in the stub
		true,  // IMAGE_DIRECTORY_ENTRY_SECURITY 
		false, // IMAGE_DIRECTORY_ENTRY_BASERELOC
		true,  // IMAGE_DIRECTORY_ENTRY_DEBUG    
		true,  // IMAGE_DIRECTORY_ENTRY_ARCHITECTURE // BUGBUG: actually, it depends on the architecture
		false, // IMAGE_DIRECTORY_ENTRY_GLOBALPTR     
		false, // IMAGE_DIRECTORY_ENTRY_TLS           
		false, // IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG   
		true,  // IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT  
		true,  // IMAGE_DIRECTORY_ENTRY_IAT           
		true,  // IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT  
		true,  // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
	};

	int errors = 0;

	for(ULONG i = 0; i < ARRAYSIZE(directoryNames); ++ i)
	{
		ULONG Size;
		PVOID Data = RtlImageDirectoryEntryToData(pStub, TRUE, i, &Size);

		if(Data)
		{
			bool state = uselessOrUnsupported[i];

			// unless /FIXED is specified, the linker will always create a relocation directory, but with
			// /FIXED it will set the IMAGE_FILE_RELOCS_STRIPPED flag, which is undesireable for debugging.
			// If the relocation directory is empty, though, it's ok for us. Still, it's useless space
			if(i == IMAGE_DIRECTORY_ENTRY_BASERELOC)
			{
				PIMAGE_BASE_RELOCATION pReloc = static_cast<PIMAGE_BASE_RELOCATION>(Data);

				if(pReloc->SizeOfBlock == sizeof(IMAGE_BASE_RELOCATION))
					state = true;
			}

			if(state)
				_ftprintf(stderr, _T("%s: the %s contains a %s data directory, which is %s\n"), _T("warning"), _T("stub"), directoryNames[i], _T("unused"));
			else
			{
				_ftprintf(stderr, _T("%s: the %s contains a %s data directory, which is %s\n"), _T("error"), _T("stub"), directoryNames[i], _T("unsupported"));
				++ errors;
			}
		}
	}

	return errors == 0;
}

bool validatePayload(PIMAGE_DOS_HEADER pPayload)
{	
	PIMAGE_NT_HEADERS pNtHeaders = RtlImageNtHeader(pPayload);

	if(pNtHeaders == NULL)
	{
		_ftprintf(stderr, _T("%s: the %s isn't a valid PE image\n"), _T("error"), _T("payload"));
		return false;
	}

	if(pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)
	{
		_ftprintf(stderr, _T("%s: the %s is a DLL, which is unsupported\n"), _T("error"), _T("payload"));
		return false;
	}

	if(hasManifest(reinterpret_cast<HMODULE>(pPayload)))
	{
		_ftprintf(stderr, _T("%s: the %s contains a %s resource, which is %s\n"), _T("error"), _T("payload"), _T("manifest"), _T("unsupported"));
		return false;
	}

	enum
	{
		Neither,
		Useless,
		Unsupported
	}
	state[] =
	{
		Useless,     // IMAGE_DIRECTORY_ENTRY_EXPORT   
		Neither,     // IMAGE_DIRECTORY_ENTRY_IMPORT   
		Useless,     // IMAGE_DIRECTORY_ENTRY_RESOURCE 
		Unsupported, // IMAGE_DIRECTORY_ENTRY_EXCEPTION
		Useless,     // IMAGE_DIRECTORY_ENTRY_SECURITY
		Neither,     // IMAGE_DIRECTORY_ENTRY_BASERELOC
		Useless,     // IMAGE_DIRECTORY_ENTRY_DEBUG
		Useless,     // IMAGE_DIRECTORY_ENTRY_ARCHITECTURE
		Unsupported, // IMAGE_DIRECTORY_ENTRY_GLOBALPTR     
		Unsupported, // IMAGE_DIRECTORY_ENTRY_TLS           
		Useless,     // IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG   
		Useless,     // IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT  
		Neither,     // IMAGE_DIRECTORY_ENTRY_IAT           
		Useless,     // IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT  
		Unsupported, // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
	};

	int errors = 0;

	for(ULONG i = 0; i < ARRAYSIZE(directoryNames); ++ i)
	{
		ULONG Size;
		PVOID Data = RtlImageDirectoryEntryToData(pPayload, TRUE, i, &Size);

		if(Data)
		{
			if(state[i] == Useless)
				_ftprintf(stderr, _T("%s: the %s contains a %s data directory, which is %s\n"), _T("warning"), _T("payload"), directoryNames[i], _T("unused"));
			else if(state[i] == Unsupported)
			{
				_ftprintf(stderr, _T("%s: the %s contains a %s data directory, which is %s\n"), _T("error"), _T("payload"), directoryNames[i], _T("unsupported"));
				++ errors;
			}
		}
	}

	return errors == 0;
}

extern "C" BYTE __ImageBase;
HINSTANCE hInstance = reinterpret_cast<HINSTANCE>(&__ImageBase);

int _tmain(int argc, _TCHAR* argv[])
{
	TCHAR szFileName[MAX_PATH + 1];
	GetModuleFileName(hInstance, szFileName, ARRAYSIZE(szFileName) - 1);

	size_t fileNamePos = 0;

	for(size_t i = 0; szFileName[i] != 0; ++ i)
	{
		if(szFileName[i] == '/' || szFileName[i] == '\\')
			fileNamePos = i + 1;
	}

	// First, load the stub
	_tcscpy_s(szFileName + fileNamePos, ARRAYSIZE(szFileName) - fileNamePos, _T("stub.dll"));

	PIMAGE_DOS_HEADER pStub = bareLoadLibrary(szFileName);

	if(!validateStub(pStub))
	{
		_ftprintf(stderr, _T("%s: %s: invalid %s\n"), _T("error"), szFileName, _T("stub"));
		return 1;
	}

	PStubEntry pfnStubEntry = RVA<PStubEntry>
	(
		pStub,
		RVA<const IMAGE_NT_HEADERS *>(pStub, pStub->e_lfanew)->OptionalHeader.AddressOfEntryPoint
	);

	// Then, load the test payload
	LPCTSTR pszFileName;

	if(argc > 1)
		pszFileName = argv[1];
	else
	{
		_tcscpy_s(szFileName + fileNamePos, ARRAYSIZE(szFileName) - fileNamePos, _T("testpayload.exe"));
		pszFileName = szFileName;
	}

	PIMAGE_DOS_HEADER pPayload = bareLoadLibrary(pszFileName);

	if(!validatePayload(pPayload))
	{
		_ftprintf(stderr, _T("%s: %s: invalid %s\n"), _T("error"), pszFileName, _T("payload"));
		return 1;
	}

	PVOID pBase;
	SIZE_T size = 0;

	MEMORY_BASIC_INFORMATION memInfo;

	VirtualQuery(pPayload, &memInfo, sizeof(memInfo));

	pBase = memInfo.AllocationBase;

	while(memInfo.AllocationBase == pBase)
	{		
		memInfo.BaseAddress = RVA<PVOID>(memInfo.BaseAddress, memInfo.RegionSize);
		size += memInfo.RegionSize;

		VirtualQuery(memInfo.BaseAddress, &memInfo, sizeof(memInfo));
	}

	DWORD ignore;
	VirtualProtect(pBase, size, PAGE_EXECUTE_READWRITE, &ignore);

	// HACK-O-RAMA FOR TESTING ONLY
	PPEB peb = NtCurrentPeb();

	CONTAINING_RECORD
	(
		peb->Ldr->InLoadOrderModuleList.Flink,
		LDR_DATA_TABLE_ENTRY,
		InLoadOrderLinks
	)->DllBase = pPayload;

	peb->ImageBaseAddress = pPayload;

	// TODO: fix command line

	// Let the stub digest the payload
	PTHREAD_START_ROUTINE pfnExeMain = pfnStubEntry(pPayload);

	return pfnExeMain(NULL);
}

// EOF
