/*
 * zrtp.org is a ZRTP protocol implementation  
 * Copyright (C) 2010 - PrivateWave Italia S.p.A.
 *  
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *  
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *  
 * For more information, please contact PrivateWave Italia S.p.A. at
 * address zorg@privatewave.com or http://www.privatewave.com
 */

#ifndef ZORG_LOG_H_
#define ZORG_LOG_H_

#include <algorithm>
#include <zorg/zorg.h>

namespace ZORG
{
namespace Log
{
namespace Internals
{

template<size_t Nbytes>
struct FullRawHexDumpBuffer
{
private:
    template<size_t N>
    struct HexSizeRequired
    {
	enum { VALUE = N * 2 };
    };

    template<size_t N, size_t MaxBytesPerLine = 16>
    struct SizeRequired
    {
    private:
	enum
	{
	    linePrefixSize = HexSizeRequired<sizeof(size_t)>::VALUE + 1,
	    linePrefixSeparatorSize = 1,
	    byteHexSize = HexSizeRequired<1>::VALUE,
	    byteHexSeparatorSize = 1,
	    hexDumpSeparatorSize = 1,
	    byteDumpSize = 1,
	    lineTerminatorSize = 1,

	    fullLines = N / MaxBytesPerLine,
	    fullLineBytes = MaxBytesPerLine,
	    fullLineHexSeparators = fullLineBytes - 1,
	    fullLineHexDumpSize = fullLineBytes * byteHexSize + fullLineHexSeparators * byteHexSeparatorSize,
	    fullLineByteDumpSize = fullLineBytes * byteDumpSize,

	    partialLines = !!(N % MaxBytesPerLine),
	    partialLineBytes = N % MaxBytesPerLine,
	    partialLineHexDumpSize = fullLineHexDumpSize, // partial lines are padded to full line length
	    partialLineByteDumpSize = partialLineBytes * byteDumpSize,

	    fullLineSize = linePrefixSize + linePrefixSeparatorSize + fullLineHexDumpSize + hexDumpSeparatorSize + fullLineByteDumpSize,
	    partialLineSize = linePrefixSize + linePrefixSeparatorSize + partialLineHexDumpSize + hexDumpSeparatorSize + partialLineByteDumpSize,

	    lines = fullLines + partialLines,
	    size = lines ? (fullLines * fullLineSize + partialLines * partialLineSize + (lines - 1) * lineTerminatorSize) : 0
	};

    public:
	enum { VALUE = size + 1 };
    };

    char m_buffer[SizeRequired<Nbytes>::VALUE];

public:
    const char * buffer() const { return m_buffer; }
};

template<size_t N> FullRawHexDumpBuffer<BitArray<N>::BYTES> hexDumpBuffer(const BitArray<N>&)
{
    return FullRawHexDumpBuffer<BitArray<N>::BYTES>();
}

const char * hexDump(const void * p, size_t n, char * dump);

template<size_t N> const char * hexDump(const BitArray<N>& x, char * buffer)
{
    return hexDump(&x, sizeof(x), buffer);
}

template<size_t N> const char * hexDump(const BitBlob<N>& x, char * buffer)
{
    return hexDump(x.bytes, x.dataSize, buffer);
}

#define ZORG_HEX_DUMP(X_) ::ZORG::Log::Internals::hexDump((X_), const_cast<char *>(::ZORG::Log::Internals::hexDumpBuffer((X_)).buffer()))

template<size_t Nbytes>
struct TextDumpBuffer
{
private:
    char m_buffer[Nbytes + 1];

public:
    char * buffer() { return m_buffer; }
    const char * buffer() const { return m_buffer; }
};

template<size_t N> TextDumpBuffer<BitArray<N>::BYTES> textDumpBuffer(const BitArray<N>&)
{
    return TextDumpBuffer<BitArray<N>::BYTES>();
}

const char * textDump(const void * p, size_t n, char * dump);

template<size_t N> const char * textDump(const BitArray<N>& x, char * buffer)
{
    return textDump(&x, sizeof(x), buffer);
}

template<size_t N> const char * textDump(const BitBlob<N>& x, char * buffer)
{
    return textDump(x.bytes, x.dataSize, buffer);
}

#define ZORG_TEXT_DUMP(X_) ::ZORG::Log::Internals::textDump((X_), const_cast<char *>(::ZORG::Log::Internals::textDumpBuffer((X_)).buffer()))

template<size_t Nbytes>
struct HexLineDumpBuffer
{
private:
    char m_buffer[Nbytes * 2 + 1];

public:
    char * buffer() { return m_buffer; }
    const char * buffer() const { return m_buffer; }
};

template<size_t N> HexLineDumpBuffer<BitArray<N>::BYTES> hexLineDumpBuffer(const BitArray<N>&)
{
    return HexLineDumpBuffer<BitArray<N>::BYTES>();
}

const char * hexLineDump(const void * p, size_t n, char * dump);

template<size_t N> const char * hexLineDump(const BitArray<N>& x, char * buffer)
{
    return hexLineDump(&x, sizeof(x), buffer);
}

template<size_t N> const char * hexLineDump(const BitBlob<N>& x, char * buffer)
{
    return hexLineDump(x.bytes, x.dataSize, buffer);
}

#define ZORG_HEX_LINE_DUMP(X_) ::ZORG::Log::Internals::hexLineDump((X_), const_cast<char *>(::ZORG::Log::Internals::hexLineDumpBuffer((X_)).buffer()))

}
}
}

#include <stdarg.h>

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef ZORG_MAX_LOG_LEVEL
#define ZORG_MAX_LOG_LEVEL 5
#endif

#ifndef ZORG_LOG_LEVEL
#if ZORG_MAX_LOG_LEVEL <= 0
#define ZORG_LOG_LEVEL() (0)
#else
extern int Zorg_LogLevel(void);
#define ZORG_LOG_LEVEL() (Zorg_LogLevel())
#endif
#endif

#if ZORG_MAX_LOG_LEVEL > 0
extern void Zorg_Log(int level, const char * context, const char * format, va_list ap);
extern void Zorg_Log_Wrapper1(const char * context, const char * format, ...);
extern void Zorg_Log_Wrapper2(const char * context, const char * format, ...);
extern void Zorg_Log_Wrapper3(const char * context, const char * format, ...);
extern void Zorg_Log_Wrapper4(const char * context, const char * format, ...);
extern void Zorg_Log_Wrapper5(const char * context, const char * format, ...);
#endif

#if ZORG_MAX_LOG_LEVEL >= 1
#define ZORG_LOG_WRAPPER1(ARGS_) Zorg_Log_Wrapper1 ARGS_
#else
#define ZORG_LOG_WRAPPER1(ARGS_) ((void)0)
#endif

#if ZORG_MAX_LOG_LEVEL >= 2
#define ZORG_LOG_WRAPPER2(ARGS_) Zorg_Log_Wrapper2 ARGS_
#else
#define ZORG_LOG_WRAPPER2(ARGS_) ((void)0)
#endif

#if ZORG_MAX_LOG_LEVEL >= 3
#define ZORG_LOG_WRAPPER3(ARGS_) Zorg_Log_Wrapper3 ARGS_
#else
#define ZORG_LOG_WRAPPER3(ARGS_) ((void)0)
#endif

#if ZORG_MAX_LOG_LEVEL >= 4
#define ZORG_LOG_WRAPPER4(ARGS_) Zorg_Log_Wrapper4 ARGS_
#else
#define ZORG_LOG_WRAPPER4(ARGS_) ((void)0)
#endif

#if ZORG_MAX_LOG_LEVEL >= 5
#define ZORG_LOG_WRAPPER5(ARGS_) Zorg_Log_Wrapper5 ARGS_
#else
#define ZORG_LOG_WRAPPER5(ARGS_) ((void)0)
#endif

#define ZORG_LOG(LEVEL_, ARGS_) \
    ((void)(((LEVEL_) <= ZORG_LOG_LEVEL()) ? ((void)(ZORG_LOG_WRAPPER##LEVEL_(ARGS_))) : ((void)0)))

#define ZORG_LOG_SUCCESS(E_, LEVEL_, ARGS_) \
    ((ZORG_SUCCESS((E_))) ? ((void)(ZORG_LOG(LEVEL_, ARGS_))) : ((void)0))

#ifdef __cplusplus
}
#endif

#endif

// EOF
