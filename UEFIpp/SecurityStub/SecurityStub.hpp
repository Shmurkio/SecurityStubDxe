#pragma once

#include "../UEFIpp.hpp"

namespace SecurityStub
{
	EFI_STATUS
	Init(
		MAYBE_UNUSED IN EFI_HANDLE ImageHandle,
		MAYBE_UNUSED IN PEFI_SYSTEM_TABLE SystemTable
	);
}