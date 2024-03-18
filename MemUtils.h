#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include<intrin.h>
#include "intel.hpp"

#define PAGE_OFFSET_SIZE 12
#define DIRECTORY_TABLE_BASE_OFFSET 0x0388


namespace MemUtils
{

    ULONG64		GetProcessDirectoryBase(_In_ PEPROCESS process);
	ULONG64		TranslateLinearAddress(ULONG64 dir_base, ULONG64 virtual_address);

	NTSTATUS	ReadPhysicalMemoryAddress(PVOID address, PVOID out_buffer, SIZE_T size, PSIZE_T bytes);
	NTSTATUS	WritePhysicalMemoryAddress(PVOID address, PVOID buffer, SIZE_T size, PSIZE_T bytes);

	NTSTATUS	ReadVirtualMemoryAddress(PEPROCESS process, PVOID address, PVOID buffer, ULONG buffer_size, SIZE_T* bytes);
    NTSTATUS	WriteVirtualMemoryAddress(PEPROCESS process, PVOID address, PVOID buffer, ULONG buffer_size, SIZE_T* bytes);

};


