#include <assert.h>
#include <stdint.h>
#include <limits.h>

#include <zorg/zorg.h>
#include <zorg/crypto.h>
#include <zorg/internal/libtomcrypt.h>

#include <tomcrypt.h>

using namespace ::ZORG;
using namespace ::ZORG::Crypto;

namespace
{

bool ltcError(Error& e, int error, const char * expr)
{
    assert(ZORG_SUCCESS(e));

    if(ZORG_FAILURE(e))
	return false;

    ErrorCode ec = LibTomCrypt::convertErrorCode(error);

    if(ec != ErrorNone)
    {
	ZORG_SET_ERROR(e, ec);
	// TODO: use expr
    }

    return ec != ErrorNone;
}

#define LTC_CHECK(E_, LTC_) (ZORG_SUCCESS((E_)) && ltcError((E_), (LTC_), #LTC_))

class ECC: public KeyExchange
{
private:
    size_t m_keySize;
    ecc_key m_key;

    static unsigned long readRandomCallback(unsigned char * out, unsigned long outlen, void * context)
    {
	Blob randbuf;
	randbuf.dataSize = 0;
	randbuf.maxSize = static_cast<size_t>(outlen);
	randbuf.buffer = out;

	ZORG_DECL_ERROR(e);

	return static_cast<unsigned long>((static_cast<RNG *>(context)->generateRandom(e, randbuf.maxSize, randbuf)).dataSize);
    }

public:
    ECC(Error& e, RNG * rng, size_t keyBits): m_keySize(keyBits)
    {
	if(ZORG_FAILURE(e))
	    return;

	ecc_make_key_2(rng, readRandomCallback, roundUpBitsToBytes(m_keySize), &m_key);
    }

    ECC(Error& e, RNG * rng, size_t keyBits, const Blob& privateKey): m_keySize(keyBits)
    {
	if(ZORG_FAILURE(e))
	    return;

	if(privateKey.dataSize != roundUpBitsToBytes(m_keySize))
	{
	    ZORG_SET_ERROR(e, ErrorKeySize);
	    return;
	}

	ecc_make_key_3(static_cast<unsigned char *>(privateKey.buffer), roundUpBitsToBytes(m_keySize), &m_key);
    }

    virtual ~ECC() 
    {
	ecc_free(&m_key);
    }

    virtual size_t getPublicKeyBits()
    {
	return (roundUpBitsToBytes(m_keySize) * 2) * CHAR_BIT;
    }

    virtual size_t getSharedSecretBits()
    {
	return m_keySize;
    }

    virtual const Blob& getPublicKey(::ZORG::Error& e, ::ZORG::Blob& publicKey)
    {
        if(ZORG_FAILURE(e))
            return NullBlob;

	size_t publicKeySize = m_key.dp->size * 2;

	if(publicKey.maxSize < publicKeySize)
	{
	    ZORG_SET_ERROR(e, ErrorBufferSize);
	    return NullBlob;
	}

	unsigned long xSize = ltc_mp.unsigned_size(m_key.pubkey.x);

	if(xSize > publicKeySize / 2)
	{
	    ZORG_SET_ERROR(e, ErrorCrypto);
	    return NullBlob;
	}

	unsigned long ySize = ltc_mp.unsigned_size(m_key.pubkey.y);

	if(ySize > publicKeySize / 2)
	{
	    ZORG_SET_ERROR(e, ErrorCrypto);
	    return NullBlob;
	}

	unsigned char * xPadding = static_cast<unsigned char *>(publicKey.buffer);
	size_t xPaddingSize = publicKeySize / 2 - xSize;

	unsigned char * yPadding = static_cast<unsigned char *>(publicKey.buffer) + publicKeySize / 2;
	size_t yPaddingSize = publicKeySize / 2 - ySize;

	unsigned char * xBuffer = xPadding + xPaddingSize;
	unsigned char * yBuffer = yPadding + yPaddingSize;

	LTC_CHECK(e, ltc_mp.unsigned_write(m_key.pubkey.x, xBuffer));
	LTC_CHECK(e, ltc_mp.unsigned_write(m_key.pubkey.y, yBuffer));

	memset(xPadding, 0, xPaddingSize);
	memset(yPadding, 0, yPaddingSize);

        if(ZORG_FAILURE(e))
            return NullBlob;

	publicKey.dataSize = publicKeySize;
        return publicKey;
    }

    virtual const Blob& agree(Error& e, const Blob& peerPublicKey, Blob& sharedSecretKey)
    {
	if(ZORG_FAILURE(e))
	    return NullBlob;

	size_t sharedKeySize = m_key.dp->size;
	size_t publicKeySize = m_key.dp->size * 2;

	if(peerPublicKey.dataSize != publicKeySize)
	{
	    ZORG_SET_ERROR(e, ErrorDataSize);
	    return NullBlob;
	}

	if(sharedSecretKey.maxSize < sharedKeySize)
	{
	    ZORG_SET_ERROR(e, ErrorBufferSize);
	    return NullBlob;
	}

	unsigned char * xBuffer = static_cast<unsigned char *>(peerPublicKey.buffer);
	unsigned char * yBuffer = static_cast<unsigned char *>(peerPublicKey.buffer) + publicKeySize / 2;

	void * x = NULL;
	void * y = NULL;
	void * z = NULL;

	LTC_CHECK(e, ltc_mp.init(&x));
	LTC_CHECK(e, ltc_mp.init(&y));
	LTC_CHECK(e, ltc_mp.init(&z));

	LTC_CHECK(e, ltc_mp.unsigned_read(x, xBuffer, static_cast<unsigned long>(publicKeySize / 2)));
	LTC_CHECK(e, ltc_mp.unsigned_read(y, yBuffer, static_cast<unsigned long>(publicKeySize / 2)));
	LTC_CHECK(e, ltc_mp.set_int(z, 1));

	ecc_key publicKey;

	publicKey.type = PK_PUBLIC;
	publicKey.idx = m_key.idx;
	publicKey.dp = m_key.dp;
	publicKey.pubkey.x = x;
	publicKey.pubkey.y = y;
	publicKey.pubkey.z = z;
	publicKey.k = NULL;

	unsigned char * sharedSecretBuffer = static_cast<unsigned char *>(sharedSecretKey.buffer);
	unsigned long sharedSecretLen = static_cast<unsigned long>(sharedSecretKey.maxSize);

	LTC_CHECK(e, ecc_shared_secret(&m_key, &publicKey, sharedSecretBuffer, &sharedSecretLen));

	if(z)
	    ltc_mp.deinit(z);

	if(y)
	    ltc_mp.deinit(y);

	if(x)
	    ltc_mp.deinit(x);

	if(ZORG_FAILURE(e))
	    return NullBlob;

	sharedSecretKey.dataSize = sharedKeySize;
	return sharedSecretKey;
    }
};

class ECCFunction: public KeyExchangeFunction
{
private:
    RNG * m_rng;
    size_t m_keySize;

public:
    ECCFunction(RNG * rng, size_t keySize): m_rng(rng), m_keySize(keySize) {}

    virtual void selfTest(Error& e)
    {
	if(ZORG_FAILURE(e))
	    return;

	switch(m_keySize)
	{
	case 256:
	    selfTestECP256(e);
	    break;

	case 384:
	    selfTestECP384(e);
	    break;

	case 521:
	    selfTestECP521(e);
	    break;

	default:
	    ZORG_UNREACHABLE_E(e);
	    break;
	}
    }

    virtual size_t getPrivateKeyBits()
    {
	return m_keySize;
    }

    virtual size_t getPublicKeyBits()
    {
	return (roundUpBitsToBytes(m_keySize) * 2) * CHAR_BIT;
    }

    virtual size_t getSharedSecretBits()
    {
	return m_keySize;
    }

    virtual KeyExchange * Create(Error& e)
    {
	return guard_new(e, new(e) ECC(e, m_rng, m_keySize));
    }

    virtual KeyExchange * Create(Error& e, const Blob& privateKey)
    {
	return guard_new(e, new(e) ECC(e, m_rng, m_keySize, privateKey));
    }
};

}

namespace ZORG
{
namespace Crypto
{
namespace Impl
{

KeyExchangeFunction * CreateEC25(Error& e, RNG * rng)
{
    ltc_mp = ltm_desc; // TODO: proper initialization
    return new(e) ECCFunction(rng, 256);
}

KeyExchangeFunction * CreateEC38(Error& e, RNG * rng)
{
    ltc_mp = ltm_desc; // TODO: proper initialization
    return new(e) ECCFunction(rng, 384);
}

KeyExchangeFunction * CreateEC52(Error& e, RNG * rng)
{
    ltc_mp = ltm_desc; // TODO: proper initialization
    return new(e) ECCFunction(rng, 521);
}

}
}
}

// EOF
