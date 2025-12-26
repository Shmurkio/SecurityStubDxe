#pragma once

#include "../UEFIpp.hpp"

namespace Crypto
{
	EFI_STATUS
	Sha256(
		IN PCVOID Buffer,
		IN CUINT64 Length,
		OUT UINT8 (&Digest)[32]
	);
}