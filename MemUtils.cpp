#include "MemUtils.h"

ULONG64 MemUtils::GetProcessDirectoryBase(PEPROCESS process)
{
	auto directory_base = *(ULONG64*)((ULONG64)process + 0x28); // 64 bit offset

	if (!directory_base) {
		directory_base = *(ULONG64*)((ULONG64)process + DIRECTORY_TABLE_BASE_OFFSET);
	}

	return directory_base;
}

ULONG64 MemUtils::TranslateLinearAddress(ULONG64 dir_base, ULONG64 virtual_address)
{
	ADDRESS_TRANSLATION_HELPER helper;
	helper.AsUInt64 = (UINT64)virtual_address;

	SIZE_T bytes = 0;
	PML4E_64 PML4E{ NULL };
	MemUtils::ReadPhysicalMemoryAddress(PVOID(dir_base + 8 * helper.AsIndex.Pml4), &PML4E, sizeof(PML4E), &bytes);

	if (!PML4E.Present)
		return NULL;

	PDPTE_64 PDPTE{ NULL };
	MemUtils::ReadPhysicalMemoryAddress(PVOID((PML4E.PageFrameNumber << PAGE_SHIFT) + 8 * helper.AsIndex.Pdpt), &PDPTE, sizeof(PDPTE), &bytes);

	if (!PDPTE.Present)
		return NULL;

	if (PDPTE.LargePage)
	{
		return ((((PDPTE_1GB_64*)&PDPTE)->PageFrameNumber << PAGE_SHIFT) + helper.AsPageOffset.Mapping1Gb);
	}

	PDE_64 PDE { NULL };
	MemUtils::ReadPhysicalMemoryAddress(PVOID((PDPTE.PageFrameNumber << PAGE_SHIFT) + 8 * helper.AsIndex.Pd), &PDE, sizeof(PDE), &bytes);

	if (!PDE.Present)
		return NULL;

	if (PDE.LargePage)
	{
		return (((PDE_2MB_64*)&PDE)->PageFrameNumber << PAGE_SHIFT) + (helper.AsPageOffset.Mapping2Mb);
	}

	PTE_64 PTE{ NULL };
	MemUtils::ReadPhysicalMemoryAddress(PVOID((PDE.PageFrameNumber<< PAGE_SHIFT) + 8 * helper.AsIndex.Pt), &PTE, sizeof(PTE), &bytes);

	if (!PTE.Present)
		return NULL;

	return  (PTE.PageFrameNumber << PAGE_SHIFT) + (helper.AsPageOffset.Mapping4Kb);
}

NTSTATUS MemUtils::ReadPhysicalMemoryAddress(PVOID address, PVOID out_buffer, SIZE_T size, PSIZE_T bytes)
{
	if (!address) return STATUS_UNSUCCESSFUL;

	MM_COPY_ADDRESS address_to_read{ 0 };
	address_to_read.PhysicalAddress.QuadPart = reinterpret_cast<LONGLONG>(address);

	return MmCopyMemory(out_buffer, address_to_read, size, MM_COPY_MEMORY_PHYSICAL, bytes);
}

NTSTATUS MemUtils::WritePhysicalMemoryAddress(PVOID address, PVOID buffer, SIZE_T size, PSIZE_T bytes)
{
	if (!address) return STATUS_UNSUCCESSFUL;

	PHYSICAL_ADDRESS address_to_write{ 0 };
	address_to_write.QuadPart = (LONGLONG)address;

	PVOID mapped_memory = MmMapIoSpaceEx(address_to_write, size, PAGE_READWRITE);
	if (!mapped_memory) return STATUS_UNSUCCESSFUL;

	memcpy(mapped_memory, buffer, size);
	*bytes = size;

	MmUnmapIoSpace(mapped_memory, size);
	return STATUS_SUCCESS;
}

NTSTATUS MemUtils::ReadVirtualMemoryAddress(PEPROCESS process, PVOID address, PVOID buffer, ULONG buffer_size, SIZE_T* bytes)
{

	auto directory_base = GetProcessDirectoryBase(process);

	if (!directory_base)
		return STATUS_UNSUCCESSFUL;

	SIZE_T curr_offset = 0;
	SIZE_T total_size = buffer_size;
	NTSTATUS nt_ret = STATUS_UNSUCCESSFUL;

	while (total_size) {

		auto current_physical_address = TranslateLinearAddress(directory_base, (ULONG64)address + curr_offset);

		if (!current_physical_address)
			return STATUS_UNSUCCESSFUL;

		ULONG64 read_size = min(PAGE_SIZE - (current_physical_address & 0xFFF), total_size);
		SIZE_T curr_bytes_read = 0;

		nt_ret = ReadPhysicalMemoryAddress((PVOID)current_physical_address, (PVOID)((ULONG64)buffer + curr_offset), read_size, &curr_bytes_read);
		total_size -= curr_bytes_read;
		curr_offset += curr_bytes_read;

		if (!NT_SUCCESS(nt_ret))
			break;

		if (bytes == 0)
			break;

	}

	if (bytes != nullptr)
		*bytes = curr_offset;

	return nt_ret;
}

NTSTATUS MemUtils::WriteVirtualMemoryAddress(PEPROCESS process, PVOID address, PVOID buffer, ULONG buffer_size, SIZE_T* bytes)
{

	auto directory_base = GetProcessDirectoryBase(process);

	if (!directory_base)
		return STATUS_UNSUCCESSFUL;

	SIZE_T curr_offset = 0;
	SIZE_T total_size = buffer_size;
	NTSTATUS nt_ret = STATUS_UNSUCCESSFUL;

	while (total_size) {

		auto current_physical_address = TranslateLinearAddress(directory_base, (ULONG64)address + curr_offset);
		
		if (!current_physical_address)
			return STATUS_UNSUCCESSFUL;

		ULONG64 write_size = min(PAGE_SIZE - (current_physical_address & 0xFFF), total_size);
		SIZE_T curr_bytes_read = 0;

		nt_ret = WritePhysicalMemoryAddress((PVOID)current_physical_address, (PVOID)((ULONG64)buffer + curr_offset), write_size, &curr_bytes_read);

		total_size -= curr_bytes_read;
		curr_offset += curr_bytes_read;

		if (!NT_SUCCESS(nt_ret))
			break;

		if (bytes == 0)
			break;

	}

	if (bytes != nullptr)
		*bytes = curr_offset;

	return nt_ret;
}

