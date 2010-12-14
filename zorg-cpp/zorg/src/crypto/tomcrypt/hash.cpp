#include <zorg/zorg.h>
#include <zorg/crypto.h>
#include <zorg/internal/libtomcrypt.h>

#include <tomcrypt.h>

using namespace ::ZORG;
using namespace ::ZORG::Crypto;

namespace ZORG
{
namespace Crypto
{
namespace Impl
{

class HMAC: public Crypto::Hash
{
private:
    hmac_state m_state;

public:
    HMAC(Error& e, int hash, const Blob& key)
    {
	if(ZORG_FAILURE(e))
	    return;

	ErrorCode ec;

	if((ec = LibTomCrypt::convertErrorCode(hmac_init(&m_state, hash, static_cast<unsigned char *>(key.buffer), static_cast<unsigned long>(key.dataSize)))) != ErrorNone)
	{
	    ZORG_SET_ERROR(e, ec);
	    return;
	}
    }

    virtual void next(Error& e, const Blob& data)
    {
	if(ZORG_FAILURE(e))
	    return;

	ErrorCode ec;

	if((ec = LibTomCrypt::convertErrorCode(hmac_process(&m_state, static_cast<unsigned char *>(data.buffer), static_cast<unsigned long>(data.dataSize)))) != ErrorNone)
	{
	    ZORG_SET_ERROR(e, ec);
	    return;
	}
    }

    virtual const Blob& finish(Error& e, Blob& hashValue)
    {
	if(ZORG_FAILURE(e))
	    return NullBlob;

	unsigned long outlen = static_cast<unsigned long>(hashValue.maxSize);
	ErrorCode ec;

	if((ec = LibTomCrypt::convertErrorCode(hmac_done(&m_state, static_cast<unsigned char *>(hashValue.buffer), &outlen))) != ErrorNone)
	{
	    ZORG_SET_ERROR(e, ec);
	    return NullBlob;
	}

	hashValue.dataSize = outlen;
	return hashValue;
    }
};

class HMAC_SHA256: public HMAC
{
public:
    HMAC_SHA256(Error& e, const Blob& key): HMAC(e, register_hash(&sha256_desc)/* FIXME: proper initialization */, key)
    {
	if(ZORG_FAILURE(e))
	    return;
    }
};

class HMAC_SHA384: public HMAC
{
public:
    HMAC_SHA384(Error& e, const Blob& key): HMAC(e, register_hash(&sha384_desc)/* FIXME: proper initialization */, key)
    {
	if(ZORG_FAILURE(e))
	    return;
    }
};

class SHA256: public Crypto::Hash
{
private:
    hash_state m_state;

public:
    SHA256(Error& e)
    {
	if(ZORG_FAILURE(e))
	    return;

	ErrorCode ec;

	if((ec = LibTomCrypt::convertErrorCode(sha256_init(&m_state))) != ErrorNone)
	{
	    ZORG_SET_ERROR(e, ec);
	    return;
	}
    }

    virtual void next(Error& e, const Blob& data)
    {
	if(ZORG_FAILURE(e))
	    return;

	ErrorCode ec;

	if((ec = LibTomCrypt::convertErrorCode(sha256_process(&m_state, static_cast<unsigned char *>(data.buffer), static_cast<unsigned long>(data.dataSize)))) != ErrorNone)
	{
	    ZORG_SET_ERROR(e, ec);
	    return;
	}
    }

    virtual const Blob& finish(Error& e, Blob& hashValue)
    {
	if(ZORG_FAILURE(e))
	    return NullBlob;

	if(hashValue.maxSize < TemplateHell::RoundUpBitsToBytes<256>::value)
	{
	    ZORG_SET_ERROR(e, ErrorBufferSize);
	    return NullBlob;
	}

	ErrorCode ec;

	if((ec = LibTomCrypt::convertErrorCode(sha256_done(&m_state, static_cast<unsigned char *>(hashValue.buffer)))) != ErrorNone)
	{
	    ZORG_SET_ERROR(e, ec);
	    return NullBlob;
	}

	hashValue.dataSize = TemplateHell::RoundUpBitsToBytes<256>::value;
	return hashValue;
    }
};

class SHA384: public Crypto::Hash
{
private:
    hash_state m_state;

public:
    SHA384(Error& e)
    {
	if(ZORG_FAILURE(e))
	    return;

	ErrorCode ec;

	if((ec = LibTomCrypt::convertErrorCode(sha384_init(&m_state))) != ErrorNone)
	{
	    ZORG_SET_ERROR(e, ec);
	    return;
	}
    }

    virtual void next(Error& e, const Blob& data)
    {
	if(ZORG_FAILURE(e))
	    return;

	ErrorCode ec;

	if((ec = LibTomCrypt::convertErrorCode(sha384_process(&m_state, static_cast<unsigned char *>(data.buffer), static_cast<unsigned long>(data.dataSize)))) != ErrorNone)
	{
	    ZORG_SET_ERROR(e, ec);
	    return;
	}
    }

    virtual const Blob& finish(Error& e, Blob& hashValue)
    {
	if(ZORG_FAILURE(e))
	    return NullBlob;

	if(hashValue.maxSize < TemplateHell::RoundUpBitsToBytes<384>::value)
	{
	    ZORG_SET_ERROR(e, ErrorBufferSize);
	    return NullBlob;
	}

	ErrorCode ec;

	if((ec = LibTomCrypt::convertErrorCode(sha384_done(&m_state, static_cast<unsigned char *>(hashValue.buffer)))) != ErrorNone)
	{
	    ZORG_SET_ERROR(e, ec);
	    return NullBlob;
	}

	hashValue.dataSize = TemplateHell::RoundUpBitsToBytes<384>::value;
	return hashValue;
    }
};

class SHA256Function: public Crypto::HashFunction
{
public:
    virtual void selfTest(Error& e)
    {
	selfTestSHA256(e);
    }

    virtual size_t getHashBits()
    {
	return 256;
    }

    virtual Hash * Create(Error& e)
    {
	return guard_new(e, new(e) SHA256(e));
    }

    virtual Hash * Create(Error& e, const Blob& key)
    {
	return guard_new(e, new(e) HMAC_SHA256(e, key));
    }
};

class SHA384Function: public Crypto::HashFunction
{
public:
    virtual void selfTest(Error& e)
    {
	selfTestSHA384(e);
    }

    virtual size_t getHashBits()
    {
	return 384;
    }

    virtual Hash * Create(Error& e)
    {
	return guard_new(e, new(e) SHA384(e));
    }

    virtual Hash * Create(Error& e, const Blob& key)
    {
	return guard_new(e, new(e) HMAC_SHA384(e, key));
    }
};

HashFunction * CreateS256(Error& e)
{
    return new(e) SHA256Function();
}

HashFunction * CreateS384(Error& e)
{
    return new(e) SHA384Function();
}

}
}
}

// EOF
