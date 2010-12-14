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

#ifndef ZORG_ZORG_H_
#define ZORG_ZORG_H_

#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

enum Zorg_ErrorCode
{
    Zorg_ErrorNone,
    Zorg_ErrorGeneral,
    Zorg_ErrorInternal,
    Zorg_ErrorInternalAbort,
    Zorg_ErrorNoMemory,
    Zorg_ErrorArgument,
    Zorg_ErrorBufferSize,
    Zorg_ErrorDataSize,
    Zorg_ErrorHexDigit,
    Zorg_ErrorKeySize,
    Zorg_ErrorSaltSize,
    Zorg_ErrorIVSize,
    Zorg_ErrorCrypto,
    Zorg_ErrorNetwork,
    Zorg_ErrorIO,
    Zorg_ErrorFileSystem,
    Zorg_ErrorZRTPStopped,
    Zorg_ErrorZRTPBadProfile,
    Zorg_ErrorZRTPUnavailable,
    Zorg_ErrorZRTPSecretNotFound,
    Zorg_ErrorZRTPBadSRTPProfile,
    Zorg_ErrorZRTPBadMultistream,
    Zorg_ErrorZRTPWrongHashImage,
    Zorg_ErrorZRTPBadSDPAttribute,
    Zorg_ErrorZRTPProtocolErrorLow = 0x1000,
    Zorg_ErrorZRTPProtocolErrorHigh = 0x1FFF
};

typedef struct Zorg_Error
{
    enum Zorg_ErrorCode code_;
#ifdef _DEBUG
    const char * file_;
    int line_;
#endif
}
Zorg_Error;

#ifdef _DEBUG
extern void Zorg_DebugSetError(Zorg_Error * e, enum Zorg_ErrorCode code, const char * file, int line);
#else

#ifdef __cplusplus
namespace
{
#endif

#if defined(__cplusplus)
inline
#elif defined(_MSC_VER)
__inline
#elif defined(__GNUC__)
__inline__
#else
static
#endif
void Zorg_SetError(Zorg_Error * e, enum Zorg_ErrorCode code)
{
    e->code_ = code;
}

#ifdef __cplusplus
}
#endif

#endif

#ifdef __cplusplus
namespace
{
#ifdef _DEBUG
inline Zorg_Error Zorg_EmptyError(const char * file, int line)
{
    Zorg_Error e = { Zorg_ErrorNone, file, line };
    return e;
}
#else
inline Zorg_Error Zorg_EmptyError()
{
    Zorg_Error e = { Zorg_ErrorNone };
    return e;
}
#endif
}

#define ZORG_IGNORE_ERROR() (const_cast<Zorg_Error&>(Zorg_EmptyError()))
#endif

#ifdef _DEBUG
#define ZORG_DECL_ERROR(E_) Zorg_Error E_ = { Zorg_ErrorNone, (__FILE__), (__LINE__) }
#define ZORG_SET_ERROR(E_, CODE_) (Zorg_DebugSetError(&(E_), (CODE_), (__FILE__), (__LINE__)))
#else
#define ZORG_DECL_ERROR(E_) Zorg_Error E_ = { Zorg_ErrorNone };
#define ZORG_SET_ERROR(E_, CODE_) (Zorg_SetError(&(E_), (CODE_)))
#endif

#define ZORG_ERROR_CODE(E_) ((E_).code_)
#define ZORG_FAILURE(E_) (ZORG_ERROR_CODE((E_)) != Zorg_ErrorNone)
#define ZORG_SUCCESS(E_) (!ZORG_FAILURE((E_)))
#define ZORG_CLEAR_ERROR(E_) ZORG_SET_ERROR((E_), Zorg_ErrorNone)

#ifdef NDEBUG
#define ZORG_ASSERT(COND_) ((void)0)
#else
#define ZORG_ASSERT(COND_) assert(COND_)
#endif

#define ZORG_UNREACHABLE() ZORG_ASSERT(!"Unreachable code was reached")
#define ZORG_UNREACHABLE_E(E_) (ZORG_UNREACHABLE(), ZORG_SET_ERROR((E_), Zorg_ErrorInternal))

struct Zorg_Blob
{
    size_t dataSize;
    size_t maxSize;
    void * buffer;
};

struct Zorg_SSRC
{
    unsigned char data[4];
};

#ifdef __cplusplus
}
#endif

#if defined(__cplusplus) && !defined(ZORG_C_API)

#include <assert.h>
#include <stdint.h>
#include <limits.h>
#include <algorithm>
#include <iterator>
#include <limits>

namespace ZORG
{
typedef ::Zorg_Error Error;
typedef ::Zorg_ErrorCode ErrorCode;

static const ErrorCode ErrorNone = Zorg_ErrorNone;
static const ErrorCode ErrorGeneral = Zorg_ErrorGeneral;
static const ErrorCode ErrorInternal = Zorg_ErrorInternal;
static const ErrorCode ErrorInternalAbort = Zorg_ErrorInternalAbort;
static const ErrorCode ErrorNoMemory = Zorg_ErrorNoMemory;
static const ErrorCode ErrorArgument = Zorg_ErrorArgument;
static const ErrorCode ErrorBufferSize = Zorg_ErrorBufferSize;
static const ErrorCode ErrorDataSize = Zorg_ErrorDataSize;
static const ErrorCode ErrorHexDigit = Zorg_ErrorHexDigit;
static const ErrorCode ErrorKeySize = Zorg_ErrorKeySize;
static const ErrorCode ErrorSaltSize = Zorg_ErrorSaltSize;
static const ErrorCode ErrorIVSize = Zorg_ErrorIVSize;
static const ErrorCode ErrorCrypto = Zorg_ErrorCrypto;
static const ErrorCode ErrorNetwork = Zorg_ErrorNetwork;
static const ErrorCode ErrorIO = Zorg_ErrorIO;
static const ErrorCode ErrorFileSystem = Zorg_ErrorFileSystem;
static const ErrorCode ErrorZRTPStopped = Zorg_ErrorZRTPStopped;
static const ErrorCode ErrorZRTPBadProfile = Zorg_ErrorZRTPBadProfile;
static const ErrorCode ErrorZRTPUnavailable = Zorg_ErrorZRTPUnavailable;
static const ErrorCode ErrorZRTPSecretNotFound = Zorg_ErrorZRTPSecretNotFound;
static const ErrorCode ErrorZRTPBadSRTPProfile = Zorg_ErrorZRTPBadSRTPProfile;
static const ErrorCode ErrorZRTPBadMultistream = Zorg_ErrorZRTPBadMultistream;
static const ErrorCode ErrorZRTPWrongHashImage = Zorg_ErrorZRTPWrongHashImage;
static const ErrorCode ErrorZRTPBadSDPAttribute = Zorg_ErrorZRTPBadSDPAttribute;
static const ErrorCode ErrorZRTPProtocolErrorLow = Zorg_ErrorZRTPProtocolErrorLow;
static const ErrorCode ErrorZRTPProtocolErrorHigh = Zorg_ErrorZRTPProtocolErrorHigh;
}

extern void * operator new(size_t n, ::ZORG::Error& e) throw();
extern void * operator new[](size_t n, ::ZORG::Error& e) throw();

extern void operator delete(void * p, ::ZORG::Error& e);
extern void operator delete[](void * p, ::ZORG::Error& e);

namespace ZORG
{

template<class T>
T * guard_new(Error& e, T * p)
{
    if(ZORG_FAILURE(e))
    {
	delete p;
	return NULL;
    }

    return p;
}

template<class T>
T * guard_new_array(Error& e, T * p)
{
    if(ZORG_FAILURE(e))
    {
	delete[] p;
	return NULL;
    }

    return p;
}

namespace TemplateHell
{

template<unsigned N, unsigned Module>
struct RoundDown
{
    enum
    {
        value = ((N) / (Module)) * (Module)
    };
};

template<unsigned N, unsigned Module>
struct RoundUp
{
    enum
    {
        value = RoundDown<N, Module>::value + !!((N) % (Module)) * (Module)
    };
};

template<unsigned N>
struct RoundUpToPow2
{
    enum
    {
        /* Source for the algorithm: http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2 */
        value = ((((((((N) - 1) | ((N) - 1) >> 1) | (((N) - 1) | ((N) - 1) >> 1) >> 2) | ((((N) - 1) | ((N) - 1) >> 1) | (((N) - 1) | ((N) - 1) >> 1) >> 2) >> 4) | (((((N) - 1) | ((N) - 1) >> 1) | (((N) - 1) | ((N) - 1) >> 1) >> 2) | ((((N) - 1) | ((N) - 1) >> 1) | (((N) - 1) | ((N) - 1) >> 1) >> 2) >> 4) >> 8) | ((((((N) - 1) | ((N) - 1) >> 1) | (((N) - 1) | ((N) - 1) >> 1) >> 2) | ((((N) - 1) | ((N) - 1) >> 1) | (((N) - 1) | ((N) - 1) >> 1) >> 2) >> 4) | (((((N) - 1) | ((N) - 1) >> 1) | (((N) - 1) | ((N) - 1) >> 1) >> 2) | ((((N) - 1) | ((N) - 1) >> 1) | (((N) - 1) | ((N) - 1) >> 1) >> 2) >> 4) >> 8) >> 16) + 1)
    };
};

template<unsigned Nbits>
struct RoundUpBitsToBytes
{
    enum
    {
	value = RoundUp<Nbits, CHAR_BIT>::value / CHAR_BIT
    };
};

template<unsigned Base, unsigned N>
struct Log
{
    enum
    {
	value = N < Base ? 0 : 1 + Log<Base, N / Base>::value
    };
};

template<unsigned Base> struct Log<Base, 0>
{
    enum
    {
	value = 0 // bleh
    };
};

template<unsigned N> struct Log2 { enum { value = Log<2, N>::value }; };
template<unsigned N> struct Log10 { enum { value = Log<2, N>::value }; };

template<unsigned N> struct BitsOf { enum { value = 1 + Log2<N>::value }; };

}

inline unsigned roundDown(unsigned n, unsigned module)
{
    return (n / module) * module;
}

inline unsigned roundUp(unsigned n, unsigned module)
{
    return roundDown(n, module) + !!((n % module) * module);
}

inline unsigned roundUpBitsToBytes(unsigned nbits)
{
    return roundUp(nbits, CHAR_BIT) / CHAR_BIT;
}

struct List;

struct List
{
private:
    List * prevEntry;
    List * nextEntry;

public:
    // TODO: iterators

    List()
    {
	prevEntry = this;
	nextEntry = this;
    }

    List& front()
    {
	return *nextEntry;
    }

    const List& front() const
    {
	return *nextEntry;
    }

    List& back()
    {
	return *prevEntry;
    }

    const List& back() const
    {
	return *prevEntry;
    }

    bool empty() const
    {
	return prevEntry == this;
    }

    void push_back(List& entry)
    {
	entry.prevEntry = this->prevEntry;
	entry.nextEntry = this;
	this->prevEntry->nextEntry = &entry;
	this->prevEntry = &entry;
    }

    void push_front(List& entry)
    {
	entry.prevEntry = this;
	entry.nextEntry = this->nextEntry;
	this->nextEntry->prevEntry = &entry;
	this->nextEntry = &entry;
    }

    void remove()
    {
	this->prevEntry->nextEntry = this->nextEntry;
	this->nextEntry->prevEntry = this->prevEntry;
	this->prevEntry = this;
	this->nextEntry = this;
    }

    void pop_back()
    {
	back().remove();
    }

    void pop_front()
    {
	front().remove();
    }
};

typedef ::Zorg_Blob Blob;

extern const Blob EmptyBlob;
extern const Blob NullBlob;

extern const Blob& copy(::ZORG::Error& e, const Blob& src, Blob& dest);
extern const Blob& truncatedCopy(::ZORG::Error& e, const Blob& src, Blob& dest);
extern const Blob& fillCopy(::ZORG::Error& e, const Blob& src, Blob& dest, uint8_t fillByte = 0);
extern const Blob& wipeData(Blob& dest);

typedef unsigned char * BlobIterator;

inline BlobIterator beginData(const Blob& x)
{
    return static_cast<BlobIterator>(x.buffer);
}

inline BlobIterator endData(const Blob& x)
{
    return static_cast<BlobIterator>(x.buffer) + x.dataSize;
}

inline int compareData(const Blob& x, const Blob& y)
{
    size_t cmpSize = std::min(x.dataSize, y.dataSize);
    int cmp = memcmp(x.buffer, y.buffer, cmpSize);

    if(cmp == 0)
    {
	if(x.dataSize < y.dataSize)
	    cmp = -1;
	else if(x.dataSize > y.dataSize)
	    cmp = 1;
    }

    return cmp;
}

inline Blob leftData(const Blob& src, ptrdiff_t bytes)
{
    Blob ret = src;

    if(bytes >= 0)
    {
	if(static_cast<size_t>(bytes) < ret.dataSize)
	    ret.dataSize = bytes;
    }
    else if(static_cast<size_t>(-bytes) <= ret.dataSize)
	ret.dataSize -= -bytes;

    return ret;
}

inline Blob rightData(const Blob& src, ptrdiff_t bytes)
{
    Blob ret = src;
    size_t displacement = 0;

    if(bytes < 0)
	displacement = -bytes;
    else if(bytes <= ret.dataSize)
	displacement = ret.dataSize - bytes;

    if(displacement <= ret.dataSize)
    {
	ret.dataSize -= displacement;
	ret.maxSize -= displacement;
	ret.buffer = static_cast<unsigned char *>(ret.buffer) + displacement;
    }

    return ret;
}

inline BlobIterator beginBuffer(const Blob& x)
{
    return static_cast<BlobIterator>(x.buffer);
}

inline BlobIterator endBuffer(const Blob& x)
{
    return static_cast<BlobIterator>(x.buffer) + x.maxSize;
}

inline Blob copy(::ZORG::Error& e, const Blob& src, const Blob& dest)
{
    Blob tmp = dest;
    return copy(e, src, tmp);
}

inline Blob truncatedCopy(::ZORG::Error& e, const Blob& src, const Blob& dest)
{
    Blob tmp = dest;
    return truncatedCopy(e, src, tmp);
}

inline Blob fillCopy(::ZORG::Error& e, const Blob& src, const Blob& dest, uint8_t fillByte = 0)
{
    Blob tmp = dest;
    return fillCopy(e, src, tmp, fillByte);
}

inline Blob wipeData(const Blob& dest)
{
    Blob tmp = dest;
    return wipeData(tmp);
}

template<class T> Blob rawObjectAsBlob(const T& obj)
{
    Blob blob = { sizeof(obj), sizeof(obj), const_cast<T *>(&obj) };
    return blob;
}

template<class T> Blob rawObjectAsBufferBlob(const T& obj)
{
    Blob blob = { 0, sizeof(obj), const_cast<T *>(&obj) };
    return blob;
}

template<class T> Blob rawArrayAsBlob(const T * arr, size_t nelems)
{
    Blob blob = { sizeof(T) * nelems, sizeof(T) * nelems, const_cast<T *>(arr) };
    return blob;
}

template<class T> Blob rawArrayAsBufferBlob(const T * arr, size_t nelems)
{
    Blob blob = { 0, sizeof(T) * nelems, const_cast<T *>(arr) };
    return blob;
}

struct StringLiteralAsBlob: public Blob
{
    template<size_t N>
    StringLiteralAsBlob(const char (& str)[N])
    {
        dataSize = sizeof(str) - sizeof(char);
        maxSize = sizeof(str);
        buffer = const_cast<char *>(&str[0]);
    }
};

template<size_t N> Blob asBlob(const char (& str)[N]) { return StringLiteralAsBlob(str); }

struct ByteArrayAsBlob: public Blob
{
    template<size_t N>
    ByteArrayAsBlob(const char (& arr)[N])
    {
        dataSize = sizeof(arr);
        maxSize = sizeof(arr);
        buffer = const_cast<char *>(&arr[0]);
    }

    template<size_t N>
    ByteArrayAsBlob(const unsigned char (& arr)[N])
    {
        dataSize = sizeof(arr);
        maxSize = sizeof(arr);
        buffer = const_cast<unsigned char *>(&arr[0]);
    }
};

template<size_t N> Blob asBlob(const unsigned char (& arr)[N]) { return ByteArrayAsBlob(arr); }

template<size_t N>
struct BitArray
{
    enum
    {
	BITS = (N),
	BYTES = TemplateHell::RoundUpBitsToBytes<BITS>::value
    };

    uint8_t bytes[BYTES];

    bool operator==(const BitArray<N>& other) const { return memcmp(bytes, other.bytes, sizeof(bytes)) == 0; }
    bool operator!=(const BitArray<N>& other) const { return memcmp(bytes, other.bytes, sizeof(bytes)) != 0; }
};

template<size_t N>
const BitArray<N>& copy(BitArray<N>& X, const BitArray<N>& Y)
{
    memcpy(&X, &Y, sizeof(X));
    return X;
}

template<class T>
inline BitArray<sizeof(T) * CHAR_BIT>& rawObject(T& o)
{
    return *reinterpret_cast<BitArray<sizeof(T) * CHAR_BIT> *>(&o);
}

template<class T>
inline const BitArray<sizeof(T) * CHAR_BIT>& rawObject(const T& o)
{
    return *reinterpret_cast<const BitArray<sizeof(T) * CHAR_BIT> *>(&o);
}

template<class T>
inline volatile BitArray<sizeof(T) * CHAR_BIT>& rawObject(volatile T& o)
{
    return *reinterpret_cast<volatile BitArray<sizeof(T) * CHAR_BIT> *>(&o);
}

template<size_t N>
inline const BitArray<N>& byteSwap(BitArray<N>& a)
{
    for(size_t i = 0; i < a.BYTES / 2; ++ i)
	std::swap(a.bytes[i], a.bytes[a.BYTES - i - 1]);

    return a;
}

inline BitArray<8> byte(int8_t value) { return rawObject(value); }

inline BitArray<16> int16_LE(int16_t value) { return rawObject(value); }
inline BitArray<32> int32_LE(int32_t value) { return rawObject(value); }
inline BitArray<64> int64_LE(int64_t value) { return rawObject(value); }

inline BitArray<16> int16_BE(int16_t value) { return byteSwap(rawObject(value)); }
inline BitArray<32> int32_BE(int32_t value) { return byteSwap(rawObject(value)); }
inline BitArray<64> int64_BE(int64_t value) { return byteSwap(rawObject(value)); }

template<size_t N> struct ByteArray: public BitArray<N * CHAR_BIT> {};

template<size_t N>
struct BitBlob: public Blob, public BitArray<N>
{
    BitBlob()
    {
	this->dataSize = 0;
	this->maxSize = sizeof(this->bytes);
	this->buffer = this->bytes;
    }

    BitBlob(const BitBlob& Y): BitArray<N>(Y)
    {
	this->dataSize = Y.dataSize;
	this->maxSize = sizeof(this->bytes);
	this->buffer = this->bytes;
    }


    BitBlob(const BitArray<N>& Y): BitArray<N>(Y)
    {
	this->dataSize = Y.BYTES;
	this->maxSize = sizeof(this->bytes);
	this->buffer = this->bytes;
    }

    const BitBlob& operator=(const BitBlob& Y)
    {
	*static_cast<BitArray<N> *>(this) = static_cast<const BitArray<N>&>(Y);
	this->dataSize = Y.dataSize;
	return *this;
    }

    const BitBlob& operator=(const BitArray<N>& Y)
    {
	*static_cast<BitArray<N> *>(this) = Y;
	this->dataSize = Y.BYTES;
	return *this;
    }

    bool operator==(const BitBlob& Y) const { return this->dataSize == Y.dataSize && *static_cast<const BitArray<N> *>(this) == static_cast<const BitArray<N>&>(Y); }
    bool operator!=(const BitBlob& Y) const { return !(*this == Y); }

    bool operator==(const BitArray<N>& Y) const { return this->dataSize == Y.BYTES && *static_cast<const BitArray<N> *>(this) == Y; }
    bool operator!=(const BitArray<N>& Y) const { return !(*this == Y); }
};

template<size_t N> struct ByteBlob: public BitBlob<N * CHAR_BIT> {};

template<size_t N>
struct Blnum: public BitArray<N>
{
    bool operator<(const Blnum<N>& other) const { return memcmp(this->bytes, other.bytes, sizeof(this->bytes)) < 0; }
    bool operator>(const Blnum<N>& other) const { return memcmp(this->bytes, other.bytes, sizeof(this->bytes)) > 0; }
    bool operator<=(const Blnum<N>& other) const { return memcmp(this->bytes, other.bytes, sizeof(this->bytes)) <= 0; }
    bool operator>=(const Blnum<N>& other) const { return memcmp(this->bytes, other.bytes, sizeof(this->bytes)) >= 0; }
};

template<size_t N> inline Blob asBlob(BitArray<N>& bitBuf) { return ByteArrayAsBlob(bitBuf.bytes); }
template<size_t N> inline Blob asBlob(const BitArray<N>& bitBuf) { return ByteArrayAsBlob(bitBuf.bytes); }
template<size_t N> inline Blob asBlob(BitBlob<N>& bitBlob) { return bitBlob; }
template<size_t N> inline Blob asBlob(const BitBlob<N>& bitBlob) { return bitBlob; }

template<size_t N, size_t Nbytes>
inline const BitArray<N>& asBitArray(const uint8_t (& bytes)[Nbytes])
{
    // C_ASSERT(TemplateHell::RoundUpBitsToBytes<N>::value <= Nbytes); // TODO
    return *reinterpret_cast<const BitArray<N> *>(&bytes);
}

template<size_t N, size_t Nbytes>
inline const BitArray<N>& asBitArray(const char (& bytes)[Nbytes])
{
    // C_ASSERT(TemplateHell::RoundUpBitsToBytes<N>::value <= Nbytes); // TODO
    return *reinterpret_cast<const BitArray<N> *>(&bytes);
}

inline uint16_t asInt16_BE(const BitArray<16>& bits)
{
    return
	(uint16_t(bits.bytes[0]) << 8) |
	(uint16_t(bits.bytes[1]) << 0);
}

inline uint32_t asInt32_BE(const BitArray<32>& bits)
{
    return
	(uint32_t(bits.bytes[0]) << 24) |
	(uint32_t(bits.bytes[1]) << 16) |
	(uint32_t(bits.bytes[2]) <<  8) |
	(uint32_t(bits.bytes[3]) <<  0);
}

inline uint64_t asInt64_BE(const BitArray<64>& bits)
{
    return
	(uint64_t(bits.bytes[0]) << 56) |
	(uint64_t(bits.bytes[1]) << 48) |
	(uint64_t(bits.bytes[2]) << 40) |
	(uint64_t(bits.bytes[3]) << 32) |
	(uint64_t(bits.bytes[4]) << 24) |
	(uint64_t(bits.bytes[5]) << 16) |
	(uint64_t(bits.bytes[6]) <<  8) |
	(uint64_t(bits.bytes[7]) <<  0);
}

namespace Internals
{
template<unsigned bits> struct Mask {};
template<> struct Mask<0> { typedef uint8_t type; };
template<> struct Mask<1> { typedef uint8_t type; };
template<> struct Mask<2> { typedef uint8_t type; };
template<> struct Mask<4> { typedef uint8_t type; };
template<> struct Mask<8> { typedef uint8_t type; };
template<> struct Mask<16> { typedef uint16_t type; };
template<> struct Mask<32> { typedef uint32_t type; };
}

template<class Enum, Enum MinValue, Enum MaxValue>
struct EnumMask
{
private:
    enum
    {
        min_bit = (MinValue) - (MinValue),
        max_bit = (MaxValue) - (MinValue),
        mask_size = max_bit + 1,
        valid_bits = (1 << mask_size) - 1
    };

    typedef typename Internals::Mask<TemplateHell::RoundUpToPow2<mask_size>::value>::type mask_type;

    static Enum bit_to_value(unsigned bit)
    {
        assert(bit >= min_bit);
        assert(bit <= max_bit);
        return Enum(bit + MinValue);
    }

    static unsigned value_to_bit(Enum value)
    {
        assert(value >= MinValue);
        assert(value <= MaxValue);
        return unsigned(value - MinValue);
    }

    static mask_type bit_to_mask(unsigned bit)
    {
        assert(bit >= min_bit);
        assert(bit <= max_bit);
        return mask_type(1) << bit;
    }

    static mask_type value_to_mask(Enum value)
    {
        assert(value >= MinValue);
        assert(value <= MaxValue);
        return bit_to_mask(value_to_bit(value));
    }

    mask_type mask;

    EnumMask<Enum, MinValue, MaxValue>(mask_type mask): mask(mask & valid_bits) {}

public:
    enum
    {
	MAX_SIZE = mask_size
    };

    static const Enum MIN_VALUE;
    static const Enum MAX_VALUE;

    EnumMask<Enum, MinValue, MaxValue>(): mask(0) {}
    EnumMask<Enum, MinValue, MaxValue>(const EnumMask<Enum, MinValue, MaxValue>& other): mask(other.mask) {}

    const EnumMask<Enum, MinValue, MaxValue>& operator=(const EnumMask<Enum, MinValue, MaxValue>& other)
    {
        mask = other.mask;
        return *this;
    }

    operator bool() const { return !!mask; }
    bool operator!() const { return !mask; }

    bool operator==(const EnumMask<Enum, MinValue, MaxValue>& other) const { return this->mask == other.mask; }
    bool operator!=(const EnumMask<Enum, MinValue, MaxValue>& other) const { return this->mask != other.mask; }

    EnumMask<Enum, MinValue, MaxValue> operator~() const { return EnumMask<Enum, MinValue, MaxValue>(~mask); }
    EnumMask<Enum, MinValue, MaxValue> operator&(const EnumMask<Enum, MinValue, MaxValue>& other) const { return EnumMask<Enum, MinValue, MaxValue>(mask & other.mask); }

    EnumMask<Enum, MinValue, MaxValue> operator|(const EnumMask<Enum, MinValue, MaxValue>& other) const
    {
        return EnumMask<Enum, MinValue, MaxValue>(mask | other.mask);
    }

    EnumMask<Enum, MinValue, MaxValue> operator+(const EnumMask<Enum, MinValue, MaxValue>& other) const { return *this | other; }
    EnumMask<Enum, MinValue, MaxValue> operator-(const EnumMask<Enum, MinValue, MaxValue>& other) const { return *this & ~other; }
    const EnumMask<Enum, MinValue, MaxValue>& operator&=(const EnumMask<Enum, MinValue, MaxValue>& other) { *this = *this & other; return *this; }
    const EnumMask<Enum, MinValue, MaxValue>& operator|=(const EnumMask<Enum, MinValue, MaxValue>& other) { *this = *this | other; return *this; }
    const EnumMask<Enum, MinValue, MaxValue>& operator+=(const EnumMask<Enum, MinValue, MaxValue>& other) { *this = *this + other; return *this; }
    const EnumMask<Enum, MinValue, MaxValue>& operator-=(const EnumMask<Enum, MinValue, MaxValue>& other) { *this = *this - other; return *this; }

    EnumMask<Enum, MinValue, MaxValue>(Enum value): mask(value_to_mask(value)) {}

    bool operator==(Enum other) const { return *this == EnumMask<Enum, MinValue, MaxValue>(other); }
    bool operator!=(Enum other) const { return *this != EnumMask<Enum, MinValue, MaxValue>(other); }

    EnumMask<Enum, MinValue, MaxValue> operator&(Enum other) const { return EnumMask<Enum, MinValue, MaxValue>(mask & EnumMask<Enum, MinValue, MaxValue>(other).mask); }
    EnumMask<Enum, MinValue, MaxValue> operator|(Enum other) const { return EnumMask<Enum, MinValue, MaxValue>(mask | EnumMask<Enum, MinValue, MaxValue>(other).mask); }
    EnumMask<Enum, MinValue, MaxValue> operator+(Enum other) const { return *this | EnumMask<Enum, MinValue, MaxValue>(other); }
    EnumMask<Enum, MinValue, MaxValue> operator-(Enum other) const { return *this & ~EnumMask<Enum, MinValue, MaxValue>(other); }
    const EnumMask<Enum, MinValue, MaxValue>& operator&=(Enum other) { return (*this &= EnumMask<Enum, MinValue, MaxValue>(other)); }
    const EnumMask<Enum, MinValue, MaxValue>& operator|=(Enum other) { return (*this |= EnumMask<Enum, MinValue, MaxValue>(other)); }
    const EnumMask<Enum, MinValue, MaxValue>& operator+=(Enum other) { return (*this += EnumMask<Enum, MinValue, MaxValue>(other)); }
    const EnumMask<Enum, MinValue, MaxValue>& operator-=(Enum other) { return (*this -= EnumMask<Enum, MinValue, MaxValue>(other)); }

    bool operator[](Enum value) const { return (*this & value) == value; }

public:
    // STL container API
    typedef size_t size_type;
    typedef Enum value_type;
    typedef Enum key_type;

    void clear() { mask = 0; }

    size_type count(Enum value) const { return !!(*this)[value]; }
    bool empty() const { return mask == 0; }
    size_type max_size() const { return mask_size; }

    size_type size() const
    {
        size_type n = 0;
        mask_type m = mask;

        for(; m; m >>= 1)
            n += m & 1;

        return n;
    }

    void swap(const EnumMask<Enum, MinValue, MaxValue>& other) { std::swap(this->mask, other.mask); }

public:
    // STL iterator range API
    struct const_iterator: public std::iterator<std::forward_iterator_tag, const Enum>
    {
    private:
        const EnumMask<Enum, MinValue, MaxValue> * mask;
        unsigned bit;

        friend struct EnumMask<Enum, MinValue, MaxValue>;

        const_iterator(const EnumMask<Enum, MinValue, MaxValue> * mask, unsigned bit): mask(mask), bit(bit) {}

    public:
        const_iterator(): mask(), bit() {}
        const_iterator(const const_iterator& other): mask(other.mask), bit(other.bit) {}
        const const_iterator& operator=(const const_iterator& other) { mask = other.mask; bit = other.bit; return *this; }

        bool operator==(const const_iterator& other) { assert(mask == other.mask); return bit == other.bit; }
        bool operator!=(const const_iterator& other) { assert(mask == other.mask); return bit != other.bit; }
        Enum operator*() const { assert(bit < mask_size); return bit_to_value(bit); }

        const const_iterator& operator++()
        {
            assert(bit < mask_size);

            for(++ bit; bit < mask_size; ++ bit)
            {
                if((*mask)[bit_to_value(bit)])
                    break;
            }

            return *this;
        }

        const_iterator operator++(int) { const_iterator prev = *this; ++ (*this); return prev; }
    };

    const_iterator begin() const
    {
        unsigned bit;

        for(bit = min_bit; bit < mask_size; ++ bit)
        {
            if((*this)[bit_to_value(bit)])
                return const_iterator(this, bit);
        }

        return end();
    }

    const_iterator end() const { return const_iterator(this, mask_size); }
};

template<class Enum, Enum MinValue, Enum MaxValue>
const Enum EnumMask<Enum, MinValue, MaxValue>::MIN_VALUE = MinValue;

template<class Enum, Enum MinValue, Enum MaxValue>
const Enum EnumMask<Enum, MinValue, MaxValue>::MAX_VALUE = MaxValue;

// Static operators
template<class Enum, Enum MinValue, Enum MaxValue>
bool operator==(Enum x, const EnumMask<Enum, MinValue, MaxValue>& y) { return EnumMask<Enum, MinValue, MaxValue>(x) == y; }

template<class Enum, Enum MinValue, Enum MaxValue>
bool operator!=(Enum x, const EnumMask<Enum, MinValue, MaxValue>& y) { return EnumMask<Enum, MinValue, MaxValue>(x) != y; }

template<class Enum, Enum MinValue, Enum MaxValue>
void swap(EnumMask<Enum, MinValue, MaxValue>& x, EnumMask<Enum, MinValue, MaxValue>& y) { x.swap(y); }

template<class Enum, Enum MinValue, Enum MaxValue>
struct EnumList
{
private:
    enum constants
    {
	internal_range = (MaxValue) - (MinValue),
	internal_range_size = internal_range + 1,
	internal_guard = 0,
	min_internal = 1,
	max_internal = min_internal + internal_range,
	list_size = internal_range_size
    };

    typedef typename Internals::Mask<TemplateHell::RoundUpToPow2<TemplateHell::BitsOf<max_internal>::value>::value>::type internal_type;

    static Enum internal_to_value(internal_type i)
    {
        assert(i >= min_internal);
        assert(i <= max_internal);
        return Enum(MinValue + (i - min_internal));
    }

    static internal_type value_to_internal(Enum value)
    {
        assert(value >= MinValue);
        assert(value <= MaxValue);
        return internal_type((value - MinValue) + min_internal);
    }

    internal_type list[list_size];

private:
    void insert_value(Enum value)
    {
	internal_type internal_value = value_to_internal(value);

	for(size_t i = 0; i < list_size; ++ i)
	{
	    if(list[i] == internal_value)
		return;

	    if(list[i] == internal_guard)
	    {
		list[i] = internal_value;

		if((i + 1) < list_size)
		    list[i + 1] = internal_guard;

		return;
	    }
	}

	assert(false);
    }

    void erase_index(internal_type i)
    {
	assert(i < list_size);
	std::copy(&list[i + 1], &list[list_size], &list[i]);
	list[list_size - 1] = internal_guard;
    }

    bool erase_value(Enum value)
    {
	internal_type internal_value = value_to_internal(value);

	for(size_t i = 0; i < list_size; ++ i)
	{
	    if(list[i] == internal_value)
	    {
		erase_index(i);
		return true;
	    }
	}

	return false;
    }

public:
    //static const Enum MIN_VALUE;
    //static const Enum MAX_VALUE;

    EnumList() { list[0] = internal_guard; }
    
    EnumList(const EnumList& other) { std::copy(other.raw_begin(), other.raw_end(), raw_begin()); }

    const EnumList& operator=(const EnumList& other)
    {
        std::copy(other.raw_begin(), other.raw_end(), raw_begin());
        return *this;
    }

    operator bool() const { return !empty(); }
    bool operator!() const { return empty(); }

    bool operator==(const EnumList<Enum, MinValue, MaxValue>& other) const
    {
	for(size_t i = 0; i < list_size; ++ i)
	{
	    if(list[i] == internal_guard)
		return other.list[i] == internal_guard;

	    if(list[i] != other.list[i])
		return false;
	}

	return true;
    }

    bool operator!=(const EnumList& other) const { return !(*this == other); }

    EnumList operator&(const EnumList& other) const { EnumList tmp = *this; tmp &= other; return tmp; }
    EnumList operator|(const EnumList& other) const { EnumList tmp = *this; tmp |= other; return tmp; }
    EnumList operator+(const EnumList& other) const { EnumList tmp = *this; tmp += other; return tmp; }
    EnumList operator-(const EnumList& other) const { EnumList tmp = *this; tmp -= other; return tmp; }
    
    const EnumList& operator&=(const EnumList& other)
    {
	for(size_t i = 0; i < list_size;)
	{
	    if(list[i] == internal_guard)
		break;

	    if(!other[internal_to_value(list[i])])
		erase_index(i);
	    else
		++ i;
	}

	return *this;
    }
    
    const EnumList& operator|=(const EnumList& other) { return *this += other; }
    
    const EnumList& operator+=(const EnumList& other)
    {
	for(size_t i = 0; i < list_size; ++ i)
	{
	    if(other.list[i] == internal_guard)
		break;

	    insert_value(internal_to_value(other.list[i]));
	}

	return *this;
    }
    
    const EnumList& operator-=(const EnumList& other)
    {
	for(size_t i = 0; i < list_size; ++ i)
	{
	    if(other.list[i] == internal_guard)
		break;

	    erase_value(internal_to_value(other.list[i]));
	}

	return *this;
    }

    explicit EnumList(Enum value)
    {
	list[0] = value_to_internal(value);

	if(list_size > 1)
	    list[list_size - 1] = internal_guard;
    }

    const EnumList& operator=(Enum other)
    {
        clear();
	insert_value(other);
        return *this;
    }

    const EnumList& operator&=(Enum other)
    {
	if((*this)[other])
	{
	    clear();
	    insert_value(other);
	}
	else
	    clear();

	return *this;
    }

    const EnumList& operator|=(Enum other) { insert_value(other); return *this; }
    const EnumList& operator+=(Enum other) { insert_value(other); return *this; }
    const EnumList& operator-=(Enum other) { erase_value(other); return *this; }
    EnumList operator&(Enum other) const { EnumList ret(*this); ret &= other; return ret; }
    EnumList operator|(Enum other) const { EnumList ret(*this); ret |= other; return ret; }
    EnumList operator+(Enum other) const { EnumList ret(*this); ret += other; return ret; }
    EnumList operator-(Enum other) const { EnumList ret(*this); ret -= other; return ret; }

    explicit EnumList(const EnumMask<Enum, MinValue, MaxValue>& other)
    {
	list[0] = internal_guard;

	for(typename EnumMask<Enum, MinValue, MaxValue>::const_iterator p = other.begin(), end = other.end(); p != end; ++ p)
	    insert_value(*p);
    }

    const EnumList& operator=(const EnumMask<Enum, MinValue, MaxValue>& other)
    {
        clear();

	for(typename EnumMask<Enum, MinValue, MaxValue>::const_iterator p = other.begin(), end = other.end(); p != end; ++ p)
	    insert_value(*p);

        return *this;
    }

    const EnumList& operator&=(const EnumMask<Enum, MinValue, MaxValue>& other)
    {
	for(typename EnumMask<Enum, MinValue, MaxValue>::const_iterator p = other.begin(), end = other.end(); p != end; ++ p)
	    (*this) &= *p;
	
	return *this;
    }

    const EnumList& operator|=(const EnumMask<Enum, MinValue, MaxValue>& other)
    {
	for(typename EnumMask<Enum, MinValue, MaxValue>::const_iterator p = other.begin(), end = other.end(); p != end; ++ p)
	    (*this) |= *p;
	
	return *this;
    }

    const EnumList& operator+=(const EnumMask<Enum, MinValue, MaxValue>& other)
    {
	for(typename EnumMask<Enum, MinValue, MaxValue>::const_iterator p = other.begin(), end = other.end(); p != end; ++ p)
	    (*this) += *p;
	
	return *this;
    }

    const EnumList& operator-=(const EnumMask<Enum, MinValue, MaxValue>& other)
    {
	for(typename EnumMask<Enum, MinValue, MaxValue>::const_iterator p = other.begin(), end = other.end(); p != end; ++ p)
	    (*this) -= *p;
	
	return *this;
    }

    EnumList operator&(const EnumMask<Enum, MinValue, MaxValue>& other) const { EnumList ret(*this); ret &= other; return ret; }
    EnumList operator|(const EnumMask<Enum, MinValue, MaxValue>& other) const { EnumList ret(*this); ret |= other; return ret; }
    EnumList operator+(const EnumMask<Enum, MinValue, MaxValue>& other) const { EnumList ret(*this); ret += other; return ret; }
    EnumList operator-(const EnumMask<Enum, MinValue, MaxValue>& other) const { EnumList ret(*this); ret -= other; return ret; }

    bool operator[](Enum value) const { return count(value) > 0; }

private:
    typedef const internal_type * raw_const_iterator;
    typedef internal_type * raw_iterator;

    raw_iterator raw_begin() { return &list[0]; }
    raw_iterator raw_end() { return &list[list_size]; }

    raw_const_iterator raw_begin() const { return &list[0]; }
    raw_const_iterator raw_end() const { return &list[list_size]; }

public:
    // STL container API
    typedef size_t size_type;
    typedef Enum value_type;
    typedef Enum key_type;

    void clear() { list[0] = internal_guard; }

    size_type count(Enum value) const { return !!(std::find(raw_begin(), raw_end(), value_to_internal(value)) != raw_end()); }
    bool empty() const { return list[0] == internal_guard; }
    size_type max_size() const { return list_size; }
    size_type size() const { return end().p - begin().p; }

    void swap(EnumList& other)
    {
	for(size_t i = 0; i < list_size; ++ i)
	    std::swap(list[i], other.list[i]);
    }

public:
    // STL iterator range API
    struct const_iterator: public std::iterator<std::forward_iterator_tag, const Enum>
    {
    private:
        friend struct EnumList<Enum, MinValue, MaxValue>;
        const internal_type * p;

        const_iterator(const internal_type * p): p(p) {}

    public:
        const_iterator(): p() {}
        const_iterator(const const_iterator& other): p(other.p) {}
        const const_iterator& operator=(const const_iterator& other) { p = other.p; return *this; }

        bool operator==(const const_iterator& other) { return p == other.p; }
        bool operator!=(const const_iterator& other) { return p != other.p; }
        Enum operator*() const { return internal_to_value(*p); }

        const const_iterator& operator++() { ++ p; return *this; }
        const_iterator operator++(int) { const_iterator prev = *this; ++ (*this); return prev; }
    };

    const_iterator begin() const { return const_iterator(raw_begin()); }
    const_iterator end() const { return const_iterator(std::find(raw_begin(), raw_end(), internal_guard)); }
};

//template<class Enum, Enum MinValue, Enum MaxValue>
//const Enum EnumList<Enum, MinValue, MaxValue>::MIN_VALUE = MinValue;
//
//template<class Enum, Enum MinValue, Enum MaxValue>
//const Enum EnumList<Enum, MinValue, MaxValue>::MAX_VALUE = MaxValue;

// Static operators
template<class Enum, Enum MinValue, Enum MaxValue>
void swap(EnumList<Enum, MinValue, MaxValue>& x, EnumList<Enum, MinValue, MaxValue>& y) { x.swap(y); }

struct SSRC: public Blnum<32> {};

}

#endif

#endif

// EOF
