#include <assert.h>
#include <stdint.h>

#include <zorg/zorg.h>
#include <zorg/crypto.h>
#include <zorg/internal/libtomcrypt.h>

#include <tomcrypt.h>

using namespace ::ZORG;
using namespace ::ZORG::Crypto;

class FortunaRandom: public RNG
{
private:
    prng_state m_rngState;

public:
    virtual void addEntropy(Error& e, const Blob& seed)
    {
	if(ZORG_FAILURE(e))
	    return;

	if(seed.dataSize == 0)
	    return;

	if(seed.dataSize > 32)
	{
	    addEntropy(e, leftData(seed, 32));
	    addEntropy(e, rightData(seed, -32));
	    return;
	}

	ErrorCode ec;

	if((ec = LibTomCrypt::convertErrorCode(fortuna_add_entropy(static_cast<unsigned char *>(seed.buffer), seed.dataSize, &m_rngState))) != ErrorNone)
	{
	    ZORG_SET_ERROR(e, ec);
	    return;
	}

	if((ec = LibTomCrypt::convertErrorCode(fortuna_ready(&m_rngState))) != ErrorNone)
	{
	    ZORG_SET_ERROR(e, ec);
	    return;
	}
    }

    virtual const Blob& generateRandom(Error& e, size_t nbyte, Blob& randbuf)
    {
	int randbyte;

	if(ZORG_FAILURE(e))
	    return NullBlob;

	if(randbuf.maxSize < nbyte)
	{
	    ZORG_SET_ERROR(e, ErrorBufferSize);
	    return NullBlob;
	}

	randbyte = fortuna_read(static_cast<unsigned char *>(randbuf.buffer), nbyte, &m_rngState);

	if(randbyte != nbyte)
	{
	    ZORG_SET_ERROR(e, ErrorCrypto);
	    return NullBlob; 
	}

	randbuf.dataSize = nbyte;
	return randbuf;
    }

    FortunaRandom(Error& e, const Blob& seed)
    {
	if(ZORG_FAILURE(e))
	    return;

	ErrorCode ec;

	if((ec = LibTomCrypt::convertErrorCode(fortuna_start(&m_rngState))) != ErrorNone)
	{
	    ZORG_SET_ERROR(e, ec);
	    return;
	}

	if(seed.dataSize)
	    addEntropy(e, seed);
	else
	    addEntropy(e, rawObjectAsBlob(this)); // no, I didn't mean *this
    }

    ~FortunaRandom()
    {
	if(fortuna_done(&m_rngState) != CRYPT_OK)
	    ZORG_UNREACHABLE();
    }
};

class FortunaFunction: public RNGFunction
{
public:
    virtual RNG * Create(Error& e, const Blob& seed)
    {
	return guard_new(e, new(e) FortunaRandom(e, seed));
    }
};

namespace ZORG
{
namespace Crypto
{
namespace Impl
{
RNGFunction * CreateRNGFunction(Error& e)
{
    return new(e) FortunaFunction();
}
}
}
}

// EOF
