#ifndef _DEBUG
#pragma code_seg(".$AAA")
#pragma const_seg(".$BBB")
#pragma data_seg(".$CCC")
#pragma bss_seg(".$DDD")
#endif

#define WIN32_LEAN_AND_MEAN
#define STRICT

#include <ntstatus.h>

extern "C"
{
	typedef long NTSTATUS;
};

#define WIN32_NO_STATUS
#include <windows.h>

extern "C"
{
#define NTOS_MODE_USER
#include <ntndk.h>
};

// EOF
