#include "Crypto.hpp"

typedef struct _SHA256_CONTEXT
{
	UINT32 State[8];
	UINT64 BitLen;
	UINT8 Data[64];
	UINT32 DataLen;
} SHA256_CONTEXT, *PSHA256_CONTEXT;

using CSHA256_CONTEXT = const SHA256_CONTEXT;
using PCSHA256_CONTEXT = const SHA256_CONTEXT*;

static
inline
constexpr
UINT32
RotR32(
	IN UINT32 X,
	IN UINT32 N
)
{
	return (X >> N) | (X << (32 - N));
}

static
inline
constexpr
UINT32
Ch(
	IN UINT32 X,
	IN UINT32 Y,
	IN UINT32 Z
)
{
	return (X & Y) ^ (~X & Z);
}

static
inline
constexpr
UINT32
Maj(
	IN UINT32 X,
	IN UINT32 Y,
	IN UINT32 Z
)
{
	return (X & Y) ^ (X & Z) ^ (Y & Z);
}

static
inline
constexpr
UINT32
Ep0(
	IN UINT32 X
)
{
	return RotR32(X, 2) ^ RotR32(X, 13) ^ RotR32(X, 22);
}

static
inline
constexpr
UINT32
Ep1(
	IN UINT32 X
)
{
	return RotR32(X, 6) ^ RotR32(X, 11) ^ RotR32(X, 25);
}

static
inline
constexpr
UINT32
Sig0(
	IN UINT32 X
)
{
	return RotR32(X, 7) ^ RotR32(X, 18) ^ (X >> 3);
}

static
inline
constexpr
UINT32
Sig1(
	IN UINT32 X
)
{
	return RotR32(X, 17) ^ RotR32(X, 19) ^ (X >> 10);
}

static
constexpr
UINT32
K[64] =
{
	0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,
	0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
	0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,
	0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
	0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,
	0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
	0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,
	0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
	0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,
	0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
	0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,
	0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
	0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,
	0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
	0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,
	0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2
};

static
inline
VOID
ZeroMemory(
	OUT PVOID Buffer,
	IN UINT64 Size
)
{
	PUINT8 Bytes = reinterpret_cast<PUINT8>(Buffer);

	for (UINT64 i = 0; i < Size; ++i)
	{
		Bytes[i] = 0;
	}
}

static
inline
UINT32
LoadBe32(
	IN PCUINT8 Data
)
{
	return (static_cast<UINT32>(Data[0]) << 24) | (static_cast<UINT32>(Data[1]) << 16) | (static_cast<UINT32>(Data[2]) << 8) | (static_cast<UINT32>(Data[3]) << 0);
}

static
inline
VOID
StoreBe32(
	OUT PUINT8 Out,
	IN UINT32 Value
)
{
	Out[0] = static_cast<UINT8>(Value >> 24);
	Out[1] = static_cast<UINT8>(Value >> 16);
	Out[2] = static_cast<UINT8>(Value >> 8);
	Out[3] = static_cast<UINT8>(Value >> 0);
}

static
VOID
Sha256Transform(
	IN OUT SHA256_CONTEXT& Ctx,
	IN CUINT8 (&Block)[64]
)
{
	UINT32 W[64];

	for (UINT32 i = 0; i < 16; ++i)
	{
		CUINT32 J = i * 4;
		W[i] = LoadBe32(&Block[J]);
	}

	for (UINT32 i = 16; i < 64; ++i)
	{
		W[i] = Sig1(W[i - 2]) + W[i - 7] + Sig0(W[i - 15]) + W[i - 16];
	}

	UINT32 A = Ctx.State[0];
	UINT32 B = Ctx.State[1];
	UINT32 C = Ctx.State[2];
	UINT32 D = Ctx.State[3];
	UINT32 E = Ctx.State[4];
	UINT32 F = Ctx.State[5];
	UINT32 G = Ctx.State[6];
	UINT32 H = Ctx.State[7];

	for (UINT32 I = 0; I < 64; ++I)
	{
		CUINT32 T1 = H + Ep1(E) + Ch(E, F, G) + K[I] + W[I];
		CUINT32 T2 = Ep0(A) + Maj(A, B, C);

		H = G;
		G = F;
		F = E;
		E = D + T1;
		D = C;
		C = B;
		B = A;
		A = T1 + T2;
	}

	Ctx.State[0] += A;
	Ctx.State[1] += B;
	Ctx.State[2] += C;
	Ctx.State[3] += D;
	Ctx.State[4] += E;
	Ctx.State[5] += F;
	Ctx.State[6] += G;
	Ctx.State[7] += H;
}

static
VOID
Sha256Init(
	OUT SHA256_CONTEXT& Ctx
)
{
	Ctx.DataLen = 0;
	Ctx.BitLen = 0;

	Ctx.State[0] = 0x6A09E667;
	Ctx.State[1] = 0xBB67AE85;
	Ctx.State[2] = 0x3C6EF372;
	Ctx.State[3] = 0xA54FF53A;
	Ctx.State[4] = 0x510E527F;
	Ctx.State[5] = 0x9B05688C;
	Ctx.State[6] = 0x1F83D9AB;
	Ctx.State[7] = 0x5BE0CD19;

	ZeroMemory(Ctx.Data, 64);
}

static
VOID
Sha256Update(
	IN OUT SHA256_CONTEXT& Ctx,
	IN     PCVOID          Buffer,
	IN     UINT64          Length
)
{
	PCUINT8 Bytes = reinterpret_cast<PCUINT8>(Buffer);

	for (UINT64 I = 0; I < Length; ++I)
	{
		Ctx.Data[Ctx.DataLen++] = Bytes[I];

		if (Ctx.DataLen == 64)
		{
			Sha256Transform(Ctx, reinterpret_cast<CUINT8(&)[64]>(Ctx.Data));
			Ctx.BitLen += 512;
			Ctx.DataLen = 0;
		}
	}
}

static
VOID
Sha256Final(
	IN OUT SHA256_CONTEXT& Ctx,
	OUT UINT8 (&Digest)[32]
)
{
	UINT32 I = Ctx.DataLen;

	if (I < 56)
	{
		Ctx.Data[I++] = 0x80;

		while (I < 56)
		{
			Ctx.Data[I++] = 0x00;
		}
	}
	else
	{
		Ctx.Data[I++] = 0x80;

		while (I < 64)
		{
			Ctx.Data[I++] = 0x00;
		}

		Sha256Transform(Ctx, reinterpret_cast<CUINT8(&)[64]>(Ctx.Data));
		ZeroMemory(Ctx.Data, 56);
	}

	Ctx.BitLen += static_cast<UINT64>(Ctx.DataLen) * 8;

	Ctx.Data[63] = static_cast<UINT8>(Ctx.BitLen >> 0);
	Ctx.Data[62] = static_cast<UINT8>(Ctx.BitLen >> 8);
	Ctx.Data[61] = static_cast<UINT8>(Ctx.BitLen >> 16);
	Ctx.Data[60] = static_cast<UINT8>(Ctx.BitLen >> 24);
	Ctx.Data[59] = static_cast<UINT8>(Ctx.BitLen >> 32);
	Ctx.Data[58] = static_cast<UINT8>(Ctx.BitLen >> 40);
	Ctx.Data[57] = static_cast<UINT8>(Ctx.BitLen >> 48);
	Ctx.Data[56] = static_cast<UINT8>(Ctx.BitLen >> 56);

	Sha256Transform(Ctx, reinterpret_cast<CUINT8(&)[64]>(Ctx.Data));

	for (UINT32 J = 0; J < 8; ++J)
	{
		StoreBe32(&Digest[J * 4], Ctx.State[J]);
	}
}

EFI_STATUS
Crypto::Sha256(
	IN PCVOID Buffer,
	IN CUINT64 Length,
	OUT UINT8(&Digest)[32]
)
{
	if (!Buffer || !Length)
	{
		return EFI_INVALID_PARAMETER;
	}

	SHA256_CONTEXT Ctx{};
	Sha256Init(Ctx);

	Sha256Update(Ctx, Buffer, Length);
	Sha256Final(Ctx, Digest);

	return EFI_SUCCESS;
}