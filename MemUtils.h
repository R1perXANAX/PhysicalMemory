#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include<intrin.h>
#include "intel.hpp"

#define MESSAGE_LOG

#ifdef MESSAGE_LOG
#define LOG(msg, ...) DbgPrintEx(0,0,msg,__VA_ARGS__)
#else
#define LOG(msg, ...)
#endif


#define PAGE_OFFSET_SIZE 12
#define DIRECTORY_TABLE_BASE_OFFSET 0x0388

static const ULONG64 PMASK = (~0xfull << 8) & 0xfffffffffull;
static const ULONG64 PLMASK = (~0ull << 42 >> 12);

union VIRTUAL_ADDRESS_4KB
{
	struct {
		ULONG64 offset : 12;
		ULONG64 pti : 9;
		ULONG64 pdi : 9;
		ULONG64 pdpt : 9;
		ULONG64 pml4i : 9;
	} bits;

	ULONG64 va;
};

union VIRTUAL_ADDRESS_2MB
{
	struct {
		ULONG64 offset : 21;
		ULONG64 pdi : 9;
		ULONG64 pdpt : 9;
		ULONG64 pml4i : 9;
	} bits;

	ULONG64 va;
};

union VIRTUAL_ADDRESS_1GB
{
	struct {
		ULONG64 offset : 30;
		ULONG64 pdpt : 9;
		ULONG64 pml4i : 9;
	} bits;

	ULONG64 va;
};


namespace MemUtils
{

    ULONG64		GetProcessDirectoryBase(_In_ PEPROCESS process);
	ULONG64		TranslateLinearAddress(ULONG64 dir_base, ULONG64 virtual_address);
	PT_ENTRY_64	GetPTE(ULONG64 dir_base, ULONG64 virtual_address);
	PT_ENTRY_64* GetPteTrue(
		PVOID VirtualAddress,
		CR3 HostCr3
	);

	NTSTATUS	ReadPhysicalMemoryAddress(PVOID address, PVOID out_buffer, SIZE_T size, PSIZE_T bytes);
	NTSTATUS	WritePhysicalMemoryAddress(PVOID address, PVOID buffer, SIZE_T size, PSIZE_T bytes);

	NTSTATUS	ReadVirtualMemoryAddress(PEPROCESS process, PVOID address, PVOID buffer, ULONG buffer_size, SIZE_T* bytes);
    NTSTATUS	WriteVirtualMemoryAddress(PEPROCESS process, PVOID address, PVOID buffer, ULONG buffer_size, SIZE_T* bytes);

};


