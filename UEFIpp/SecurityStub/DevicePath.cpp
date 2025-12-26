#include "DevicePath.hpp"

static PEFI_DEVICE_PATH_TO_TEXT_PROTOCOL gDpToText = nullptr;

static
EFI_STATUS
Init(
	VOID
)
{
	if (!gDpToText)
	{
		return gBS->LocateProtocol(const_cast<PCEFI_GUID>(&gEfiDevicePathToTextProtocolGuid), nullptr, reinterpret_cast<PVOID*>(&gDpToText));
	}

	return EFI_SUCCESS;
}

static
PCSTR
WideToAscii(
	IN PCWSTR Wide
)
{
	if (!Wide)
	{
		return nullptr;
	}

	UINT64 Length = 0;

	while (Wide[Length])
	{
		++Length;
	}

	PCHAR Ascii = new CHAR[Length + 1];

	if (!Ascii)
	{
		return nullptr;
	}

	for (UINT64 i = 0; i < Length; ++i)
	{
		WCHAR C = Wide[i];
		Ascii[i] = (C <= 0x7F) ? static_cast<CHAR>(C) : '?';
	}

	Ascii[Length] = '\0';

	return Ascii;
}

PCSTR
DevicePath::FileToString(
	IN PCEFI_DEVICE_PATH_PROTOCOL File
)
{
	if (!File)
	{
		return nullptr;
	}

	if (Init() != EFI_SUCCESS)
	{
		return nullptr;
	}

	PCWSTR StringW = gDpToText->ConvertDevicePathToPath(File, true, true);
	PCSTR String = WideToAscii(StringW);

	delete[] StringW;

	return String;
}