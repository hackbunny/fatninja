#include "stdafx.h"

#pragma intrinsic(strcmp)
#pragma intrinsic(strlen)

template<class T, class OffT> static __forceinline T Rva(const void * base, OffT offset)
{
	return static_cast<T>(static_cast<const void *>(static_cast<const unsigned char *>(base) + offset));
}

template<class T, class OffT> static __forceinline T Rva(void * base, OffT offset)
{
	return static_cast<T>(static_cast<void *>(static_cast<unsigned char *>(base) + offset));
}

template<class OffT> static __forceinline const void * Rva(const void * base, OffT offset)
{
	return Rva<const void *>(base, offset);
}

template<class OffT> static __forceinline void * Rva(void * base, OffT offset)
{
	return Rva<void *>(base, offset);
}

PTHREAD_START_ROUTINE NTAPI StubEntry(PIMAGE_DOS_HEADER payload)
{
	// PHASE 1: initialization
	PTEB teb = NtCurrentTeb();
	PPEB peb = teb->ProcessEnvironmentBlock;
	PPEB_LDR_DATA ldr = peb->Ldr;

	const VOID * ntdll =
		CONTAINING_RECORD
		(
			CONTAINING_RECORD
			(
				peb->Ldr->InLoadOrderModuleList.Flink,
				LDR_DATA_TABLE_ENTRY,
				InLoadOrderLinks
			)->InLoadOrderLinks.Flink,
			LDR_DATA_TABLE_ENTRY,
			InLoadOrderLinks
		)->DllBase;

	const IMAGE_NT_HEADERS * header =
		Rva<const IMAGE_NT_HEADERS *>
		(
			ntdll,
			static_cast<const IMAGE_DOS_HEADER *>(ntdll)->e_lfanew
		);

	const IMAGE_EXPORT_DIRECTORY * exports =
		Rva<const IMAGE_EXPORT_DIRECTORY *>
		(
			ntdll,
			header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
		);

	const ULONG * exportNames = Rva<const ULONG *>(ntdll, exports->AddressOfNames);

	ULONG_PTR lbound = 0;
	ULONG_PTR ubound = exports->NumberOfNames;

	char szGetProcAddress[] = { 'L', 'd', 'r', 'G', 'e', 't', 'P', 'r', 'o', 'c', 'e', 'd', 'u', 'r', 'e', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };

	typedef NTSTATUS (NTAPI * PLdrGetProcedureAddress)(PVOID, PANSI_STRING, ULONG, PVOID *);
	PLdrGetProcedureAddress pfnLdrGetProcedureAddress = NULL;

	while(lbound < ubound)
	{
		ULONG_PTR i = (lbound + ubound) / 2;
		const char * name = Rva<const char *>(ntdll, exportNames[i]);

		int d = strcmp(szGetProcAddress, name);

		if(d == 0)
		{
			ULONG nameOrdinal = Rva<const USHORT *>(ntdll, exports->AddressOfNameOrdinals)[i];
			ULONG procRVA = Rva<const ULONG *>(ntdll, exports->AddressOfFunctions)[nameOrdinal];
			pfnLdrGetProcedureAddress = Rva<PLdrGetProcedureAddress>(ntdll, procRVA);
			break;
		}
		else if(d < 0)
			ubound = i;
		else
			lbound = i + 1;
	}

	typedef NTSTATUS (NTAPI * PLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PVOID *);
	typedef NTSTATUS (NTAPI * PLdrUnloadDll)(PVOID);
	typedef PIMAGE_BASE_RELOCATION (NTAPI * PLdrProcessRelocationBlock)(PVOID, ULONG, PUSHORT, LONG_PTR);
	typedef NTSTATUS (NTAPI * PNtFlushInstructionCache)(HANDLE, PVOID, ULONG);
	typedef BOOLEAN (NTAPI * PRtlCreateUnicodeStringFromAsciiz)(PUNICODE_STRING, PCSZ);
	typedef VOID (NTAPI * PRtlFreeUnicodeString)(PUNICODE_STRING);

	PLdrLoadDll pfnLdrLoadDll = NULL;
	PLdrUnloadDll pfnLdrUnloadDll = NULL;
	PLdrProcessRelocationBlock pfnLdrProcessRelocationBlock = NULL;
	PNtFlushInstructionCache pnfNtFlushInstructionCache = NULL;
	PRtlCreateUnicodeStringFromAsciiz pfnRtlCreateUnicodeStringFromAsciiz = NULL;
	PRtlFreeUnicodeString pfnRtlFreeUnicodeString = NULL;

	char szLdrLoadDll[] = { 'L', 'd', 'r', 'L', 'o', 'a', 'd', 'D', 'l', 'l', 0 };
	char szLdrUnloadDll[] = { 'L', 'd', 'r', 'U', 'n', 'l', 'o', 'a', 'd', 'D', 'l', 'l', 0 };
	char szLdrProcessRelocationBlock[] = { 'L', 'd', 'r', 'P', 'r', 'o', 'c', 'e', 's', 's', 'R', 'e', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n', 'B', 'l', 'o', 'c', 'k', 0 };
	char szNtFlushInstructionCache[] = { 'N', 't', 'F', 'l', 'u', 's', 'h', 'I', 'n', 's', 't', 'r', 'u', 'c', 't', 'i', 'o', 'n', 'C', 'a', 'c', 'h', 'e', 0 };
	char szRtlCreateUnicodeStringFromAsciiz[] = { 'R', 't', 'l', 'C', 'r', 'e', 'a', 't', 'e', 'U', 'n', 'i', 'c', 'o', 'd', 'e', 'S', 't', 'r', 'i', 'n', 'g', 'F', 'r', 'o', 'm', 'A', 's', 'c', 'i', 'i', 'z', 0 };
	char szRtlFreeUnicodeString[] = { 'R', 't', 'l', 'F', 'r', 'e', 'e', 'U', 'n', 'i', 'c', 'o', 'd', 'e', 'S', 't', 'r', 'i', 'n', 'g', 0 };

	ANSI_STRING a_strProcNames[] =
	{
		RTL_CONSTANT_STRING(szLdrLoadDll),
		RTL_CONSTANT_STRING(szLdrUnloadDll),
		RTL_CONSTANT_STRING(szLdrProcessRelocationBlock),
		RTL_CONSTANT_STRING(szNtFlushInstructionCache),
		RTL_CONSTANT_STRING(szRtlCreateUnicodeStringFromAsciiz),
		RTL_CONSTANT_STRING(szRtlFreeUnicodeString),
	};

	PVOID * a_pfnProcAddrs[] =
	{
		reinterpret_cast<PVOID *>(&pfnLdrLoadDll),
		reinterpret_cast<PVOID *>(&pfnLdrUnloadDll),
		reinterpret_cast<PVOID *>(&pfnLdrProcessRelocationBlock),
		reinterpret_cast<PVOID *>(&pnfNtFlushInstructionCache),
		reinterpret_cast<PVOID *>(&pfnRtlCreateUnicodeStringFromAsciiz),
		reinterpret_cast<PVOID *>(&pfnRtlFreeUnicodeString),
	};

	C_ASSERT(ARRAYSIZE(a_strProcNames) == ARRAYSIZE(a_pfnProcAddrs));

	for(unsigned i = 0; i < ARRAYSIZE(a_strProcNames); ++ i)
		pfnLdrGetProcedureAddress(const_cast<PVOID>(ntdll), &a_strProcNames[i], 0, a_pfnProcAddrs[i]);

	// PHASE 2: payload relocation
	PIMAGE_NT_HEADERS payloadHeader = Rva<PIMAGE_NT_HEADERS>(payload, payload->e_lfanew);	
	
	// Relocate code
	LONG_PTR delta = reinterpret_cast<LONG_PTR>(payload) - payloadHeader->OptionalHeader.ImageBase;

	if(delta)
	{
		LONG delta32 = static_cast<LONG>(delta);

		PIMAGE_DATA_DIRECTORY relocDir = &payloadHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		ULONG remainingSize = relocDir->Size;
		PIMAGE_BASE_RELOCATION relocCur = Rva<PIMAGE_BASE_RELOCATION>(payload, relocDir->VirtualAddress);

		while(remainingSize)
		{
			remainingSize -= relocCur->SizeOfBlock;

			PVOID page = Rva(payload, relocCur->VirtualAddress);
			ULONG count = static_cast<ULONG>((relocCur->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT));
			PUSHORT typeOffset = reinterpret_cast<PUSHORT>(relocCur + 1);

			relocCur = pfnLdrProcessRelocationBlock(page, count, typeOffset, delta);
		}
	}

	// Resolve external references
	PIMAGE_DATA_DIRECTORY importsDir = &payloadHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if(importsDir->VirtualAddress && importsDir->Size)
	{
		PIMAGE_IMPORT_DESCRIPTOR imports = Rva<PIMAGE_IMPORT_DESCRIPTOR>(payload, importsDir->VirtualAddress);		

		for(PIMAGE_IMPORT_DESCRIPTOR importCur = imports; importCur->Name != 0; ++ importCur)
		{
			const char * importName = Rva<char *>(payload, importCur->Name);
			UNICODE_STRING dllName;

			if(pfnRtlCreateUnicodeStringFromAsciiz(&dllName, importName))
			{
				PVOID dllBase;

				if(NT_SUCCESS(pfnLdrLoadDll(NULL, 0, &dllName, &dllBase)))
				{
					PVOID * importAddr = Rva<PVOID *>(payload, importCur->FirstThunk);
					PIMAGE_THUNK_DATA importName;

					if(importCur->OriginalFirstThunk)
						importName = Rva<PIMAGE_THUNK_DATA>(payload, importCur->OriginalFirstThunk);
					else
						importName = Rva<PIMAGE_THUNK_DATA>(payload, importCur->FirstThunk);

					for(; importName->u1.ForwarderString != 0; ++ importName, ++ importAddr)
					{
						// import by ordinal
						if(IMAGE_SNAP_BY_ORDINAL(importName->u1.Ordinal))
							pfnLdrGetProcedureAddress(dllBase, NULL, IMAGE_ORDINAL(importName->u1.Ordinal), importAddr);
						// import by name
						else
						{
							BYTE * pImportName = Rva<PIMAGE_IMPORT_BY_NAME>(payload, importName->u1.AddressOfData)->Name;
							char * pszImportName = reinterpret_cast<char *>(pImportName);

							ANSI_STRING strImportName;
							strImportName.Length = static_cast<USHORT>(strlen(pszImportName));
							strImportName.MaximumLength = strImportName.Length;
							strImportName.Buffer = pszImportName;

							pfnLdrGetProcedureAddress(dllBase, &strImportName, 0, importAddr);
						}
					}
				}

				pfnRtlFreeUnicodeString(&dllName);
			}
		}
	}

	// Flush instruction cache
	pnfNtFlushInstructionCache(NtCurrentProcess(), payload, payloadHeader->OptionalHeader.SizeOfImage);

	// PHASE 3: return the payload's entry point address
	PTHREAD_START_ROUTINE pfnPayloadMain = NULL;

	if(payloadHeader->OptionalHeader.AddressOfEntryPoint)
		pfnPayloadMain = Rva<PTHREAD_START_ROUTINE>(payload, payloadHeader->OptionalHeader.AddressOfEntryPoint);

	// FINISH!
	return pfnPayloadMain;
}

// EOF
