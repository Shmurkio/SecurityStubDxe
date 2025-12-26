#pragma once

#include "../UEFIpp.hpp"

namespace DevicePath
{
	PCSTR
	FileToString(
		IN PCEFI_DEVICE_PATH_PROTOCOL File
	);
}