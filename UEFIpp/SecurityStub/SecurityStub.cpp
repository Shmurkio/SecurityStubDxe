#include "SecurityStub.hpp"
#include "DevicePath.hpp"
#include "Crypto.hpp"

constexpr EFI_GUID gEfiSecurity2ArchProtocolGuid = { 0x94AB2F58, 0x1438, 0x4EF1, { 0x91, 0x52, 0x18, 0x94, 0x1A, 0x3A, 0x0E, 0x68 } };

typedef struct _EFI_SECURITY2_ARCH_PROTOCOL EFI_SECURITY2_ARCH_PROTOCOL, *PEFI_SECURITY2_ARCH_PROTOCOL;
using CEFI_SECURITY2_ARCH_PROTOCOL = const EFI_SECURITY2_ARCH_PROTOCOL;
using PCEFI_SECURITY2_ARCH_PROTOCOL = const EFI_SECURITY2_ARCH_PROTOCOL*;

using EfiSecurity2FileAuthenticationFn = EFI_STATUS(__cdecl)(
	IN PCEFI_SECURITY2_ARCH_PROTOCOL This,
	IN PCEFI_DEVICE_PATH_PROTOCOL File,
	IN PCVOID FileBuffer,
	IN CUINT64 FileSize,
	IN CBOOLEAN BootPolicy
);

typedef struct _EFI_SECURITY2_ARCH_PROTOCOL
{
	EfiSecurity2FileAuthenticationFn* FileAuthentication;
} EFI_SECURITY2_ARCH_PROTOCOL, *PEFI_SECURITY2_ARCH_PROTOCOL;

constexpr EFI_GUID gEfiSecurityArchProtocolGuid = { 0xA46423E3, 0x4617, 0x49F1, { 0xB9, 0xFF, 0xD1, 0xBF, 0xA9, 0x11, 0x58, 0x39 } };

typedef struct _EFI_SECURITY_ARCH_PROTOCOL EFI_SECURITY_ARCH_PROTOCOL, *PEFI_SECURITY_ARCH_PROTOCOL;
using CEFI_SECURITY_ARCH_PROTOCOL = const EFI_SECURITY_ARCH_PROTOCOL;
using PCEFI_SECURITY_ARCH_PROTOCOL = const EFI_SECURITY_ARCH_PROTOCOL*;

using EfiSecurityFileAuthenticationStateFn = EFI_STATUS(__cdecl)(
	IN PCEFI_SECURITY_ARCH_PROTOCOL This,
	IN CUINT32 AuthenticationStatus,
	IN PCEFI_DEVICE_PATH_PROTOCOL File
);

typedef struct _EFI_SECURITY_ARCH_PROTOCOL
{
	EfiSecurityFileAuthenticationStateFn* FileAuthenticationState;
} EFI_SECURITY_ARCH_PROTOCOL, *PEFI_SECURITY_ARCH_PROTOCOL;

static
inline
VOID
LogDigest32(
	IN CUINT8 (&Digest)[32]
)
{
	for (UINT32 i = 0; i < 32; ++i)
	{
		CUINT8 Byte = Digest[i];
		CUINT8 High = static_cast<UINT8>((Byte >> 4) & 0x0F);
		CUINT8 Low = static_cast<UINT8>((Byte >> 0) & 0x0F);
		CCHAR HighC = static_cast<CHAR>((High < 10) ? ('0' + High) : ('A' + (High - 10)));
		CCHAR LowC = static_cast<CHAR>((Low < 10) ? ('0' + Low) : ('A' + (Low - 10)));
		Serial::Out << HighC << LowC;
	}
}

static
CBOOLEAN
IsHashValid(
	IN CUINT8 (&Digest)[32]
)
{
	// To be implemented...
	return true;
}

static UINT64 gFileAuthenticationIndex = 0, gFileAuthenticationStateIndex = 0;

static
EFI_STATUS
__cdecl
FileAuthentication(
	IN PCEFI_SECURITY2_ARCH_PROTOCOL This,
	IN PCEFI_DEVICE_PATH_PROTOCOL File,
	IN PCVOID FileBuffer,
	IN CUINT64 FileSize,
	IN CBOOLEAN BootPolicy
)
{
	// Log the function call.
	Serial::Out << "[SecurityStub] FileAuthentication call #" << ++gFileAuthenticationIndex << Serial::Endl;

	// Convert File to string.
	PCSTR FileStr = DevicePath::FileToString(File);
	PCSTR SafeStr = FileStr ? FileStr : "<NULL>";

	// Routine for files.
	if (FileBuffer && FileSize)
	{
		Serial::Out << "[+] File: " << SafeStr << Serial::Endl
			<< "[+] File buffer: 0x" << Serial::Hex << FileBuffer << Serial::Dec << Serial::Endl
			<< "[+] File size: " << FileSize << Serial::Endl
			<< "[+] Boot policy: " << BootPolicy << Serial::Endl;

		// Calculate SHA256 hash.
		UINT8 Digest[32]{};
		
		EFI_STATUS Status = Crypto::Sha256(FileBuffer, FileSize, Digest);

		if (Status != EFI_SUCCESS)
		{
			Serial::Out << "[!] SHA256 hash calculation failed with status 0x" << Serial::Hex << Status << Serial::Endl;
			delete[] FileStr;
			return Status;
		}

		// Log SHA256 hash.
		Serial::Out << "[+] SHA256 hash: ";
		LogDigest32(Digest);
		Serial::Out << Serial::Endl;

		// Validate SHA256 hash.
		if (!IsHashValid(Digest))
		{
			Serial::Out << "[!] SHA256 hash is invalid" << Serial::Endl;
			delete[] FileStr;
			return EFI_SECURITY_VIOLATION;
		}

		Serial::Out << "[+] SHA256 hash is valid" << Serial::Endl;
	}
	// Routine for non-files.
	else
	{
		Serial::Out << "[+] Device path: " << SafeStr << Serial::Endl
			<< "[+] Boot policy: " << BootPolicy << Serial::Endl
			<< "[i] Validation to be implemented" << Serial::Endl;
	}

	delete[] FileStr;

	return EFI_SUCCESS;
}

static CEFI_SECURITY2_ARCH_PROTOCOL gSecurity2Stub = {
	FileAuthentication
};

static
EFI_STATUS
__cdecl
FileAuthenticationState(
	IN PCEFI_SECURITY_ARCH_PROTOCOL This,
	IN CUINT32 AuthenticationStatus,
	IN PCEFI_DEVICE_PATH_PROTOCOL File
)
{
	// Log the function call.
	Serial::Out << "[SecurityStub] FileAuthenticationState call #" << ++gFileAuthenticationStateIndex << Serial::Endl;

	// Convert File to string.
	PCSTR FileStr = DevicePath::FileToString(File);
	PCSTR SafeStr = FileStr ? FileStr : "<NULL>";

	Serial::Out << "[+] Device path: " << SafeStr << Serial::Endl
		<< "[+] Authentication status: 0x" << Serial::Hex << AuthenticationStatus << Serial::Dec << Serial::Endl
		<< "[i] Validation to be implemented" << Serial::Endl;

	return EFI_SUCCESS;
}

static EFI_SECURITY_ARCH_PROTOCOL gSecurityStub = {
  FileAuthenticationState
};

EFI_STATUS
SecurityStub::Init(
	MAYBE_UNUSED IN EFI_HANDLE ImageHandle,
	MAYBE_UNUSED IN PEFI_SYSTEM_TABLE SystemTable
)
{
	Serial::Out << "[SecurityStub] Installing protocols... " << Serial::Endl;
	EFI_STATUS Status2 = gBS->InstallProtocolInterface(&ImageHandle, const_cast<PCEFI_GUID>(&gEfiSecurity2ArchProtocolGuid), EFI_NATIVE_INTERFACE, const_cast<PVOID>(reinterpret_cast<PCVOID>(&gSecurity2Stub)));
	Serial::Out << "[+] EFI_SECURITY2_ARCH_PROTOCOL status: 0x" << Serial::Hex << Status2 << Serial::Dec << Serial::Endl;

	EFI_STATUS Status1 = gBS->InstallProtocolInterface(&ImageHandle, const_cast<PCEFI_GUID>(&gEfiSecurityArchProtocolGuid), EFI_NATIVE_INTERFACE, const_cast<PVOID>(reinterpret_cast<PCVOID>(&gSecurityStub)));
	Serial::Out << "[+] EFI_SECURITY_ARCH_PROTOCOL status: 0x" << Serial::Hex << Status1 << Serial::Dec << Serial::Endl;

	if (Status2 != EFI_SUCCESS)
	{
		return Status2;
	}
	else if (Status1 != EFI_SUCCESS)
	{
		return Status1;
	}

	return EFI_SUCCESS;
}