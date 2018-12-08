#pragma once

#include <tchar.h>

#include <stdio.h>
#include <iterator>
#include <algorithm>

#define WIN32_LEAN_AND_MEAN
#define STRICT
#define NOMINMAX

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
