#include <stdint.h>
#include <limits.h>
#include <iterator>

#include <zorg/zorg.h>
#include <zorg/crypto.h>

#include <tommath.h>

using namespace ::ZORG;
using namespace ::ZORG::Crypto;

namespace
{

bool mpError(Error& e, int error)
{
    assert(ZORG_SUCCESS(e));

    if(ZORG_FAILURE(e))
	return false;

    switch(error)
    {
    case MP_OKAY:
	return true;

    case MP_MEM:
	ZORG_SET_ERROR(e, ErrorNoMemory);
	break;

    case MP_VAL:
    default:
	ZORG_SET_ERROR(e, ErrorInternal);
	break;
    }

    return false;
}

#define MP_CHECK(E_, MP_) (ZORG_SUCCESS((E_)) && mpError((E_), (MP_)))

class DH: public KeyExchange
{
private:
    size_t m_primeSize;
    mp_int m_privKey;
    mp_int m_prime;
    mp_int m_generator;

public:
    DH(Error& e, const DHGroup& group, RNG * rng, const Blob& privateKey): m_primeSize(group.prime.dataSize * CHAR_BIT), m_privKey(), m_prime(), m_generator()
    {
	if(ZORG_FAILURE(e))
	    return;

	if(privateKey.dataSize != 0 && privateKey.dataSize != group.prime.dataSize)
	{
	    ZORG_SET_ERROR(e, ErrorKeySize);
	    return;
	}

	MP_CHECK(e, mp_init(&m_privKey));
	MP_CHECK(e, mp_init(&m_prime));
	MP_CHECK(e, mp_init(&m_generator));

	if(privateKey.dataSize == 0)
	{
	    unsigned char * privKeyRawBytes = new(e) unsigned char[group.prime.dataSize];
	    rng->generateRandom(e, rawArrayAsBlob(privKeyRawBytes, group.prime.dataSize));
	    MP_CHECK(e, mp_read_unsigned_bin(&m_privKey, privKeyRawBytes, group.prime.dataSize));
	    delete[] privKeyRawBytes;
	}
	else
	{
	    assert(privateKey.dataSize == group.prime.dataSize);
	    MP_CHECK(e, mp_read_unsigned_bin(&m_privKey, static_cast<unsigned char *>(privateKey.buffer), static_cast<int>(privateKey.dataSize)));
	}

	MP_CHECK(e, mp_read_unsigned_bin(&m_prime, static_cast<unsigned char *>(group.prime.buffer), static_cast<int>(group.prime.dataSize)));
	MP_CHECK(e, mp_read_unsigned_bin(&m_generator, static_cast<unsigned char *>(group.generator.buffer), static_cast<int>(group.generator.dataSize)));
    }

    virtual ~DH()
    {
	mp_clear(&m_privKey);
	mp_clear(&m_prime);
	mp_clear(&m_generator);
    }

    virtual size_t getPublicKeyBits()
    {
	return m_primeSize;
    }

    virtual size_t getSharedSecretBits()
    {
	return m_primeSize;
    }

    virtual const Blob& getPublicKey(Error& e, Blob& publicKey)
    {
	if(ZORG_FAILURE(e))
	    return NullBlob;

	mp_int mpPublicKey;

	if(!MP_CHECK(e, mp_init(&mpPublicKey)))
	    return NullBlob;

	MP_CHECK(e, mp_exptmod(&m_generator, &m_privKey, &m_prime, &mpPublicKey));

	int publicKeySize = mp_unsigned_bin_size(&mpPublicKey);

	if(publicKey.maxSize < static_cast<size_t>(publicKeySize))
	    ZORG_SET_ERROR(e, ErrorBufferSize);

	MP_CHECK(e, mp_to_unsigned_bin(&mpPublicKey, static_cast<unsigned char *>(publicKey.buffer)));

	mp_clear(&mpPublicKey);

	if(ZORG_FAILURE(e))
	    return NullBlob;

	publicKey.dataSize = publicKeySize;
	return publicKey;
    }

    virtual const Blob& agree(Error& e, const Blob& peerPublicKey, Blob& sharedSecretKey)
    {
	if(ZORG_FAILURE(e))
	    return NullBlob;

	mp_int mpPeerPublicKey;
	MP_CHECK(e, mp_init(&mpPeerPublicKey));
	MP_CHECK(e, mp_read_unsigned_bin(&mpPeerPublicKey, static_cast<unsigned char *>(peerPublicKey.buffer), static_cast<int>(peerPublicKey.dataSize)));

	mp_int mpSharedSecretKey;
	MP_CHECK(e, mp_init(&mpSharedSecretKey));

	MP_CHECK(e, mp_exptmod(&mpPeerPublicKey, &m_privKey, &m_prime, &mpSharedSecretKey));
	mp_clear(&mpPeerPublicKey);

	unsigned long sharedSecretKeyLen = static_cast<unsigned long>(sharedSecretKey.maxSize);
	MP_CHECK(e, mp_to_unsigned_bin_n(&mpSharedSecretKey, static_cast<unsigned char *>(sharedSecretKey.buffer), &sharedSecretKeyLen));
	mp_clear(&mpSharedSecretKey);

	if(ZORG_FAILURE(e))
	    return NullBlob;

	sharedSecretKey.dataSize = static_cast<size_t>(sharedSecretKeyLen);
	return sharedSecretKey;
    }
};


class DHFunction: public KeyExchangeFunction
{
private:
    const DHGroup& m_group;
    RNG * m_rng;

public:
    DHFunction(const DHGroup& group, RNG * rng): m_group(group), m_rng(rng) {}
    virtual ~DHFunction() {}

    virtual void selfTest(Error& e)
    {
	// TODO
    }

    virtual size_t getPrivateKeyBits() { return m_group.prime.dataSize * CHAR_BIT; }
    virtual size_t getPublicKeyBits() { return m_group.prime.dataSize * CHAR_BIT; }
    virtual size_t getSharedSecretBits() { return m_group.prime.dataSize * CHAR_BIT; }

    virtual KeyExchange * Create(Error& e)
    {
	return guard_new(e, new(e) DH(e, m_group, m_rng, NullBlob));
    }

    virtual KeyExchange * Create(Error& e, const Blob& privateKey)
    {
	return guard_new(e, new(e) DH(e, m_group, m_rng, privateKey));
    }
};

}

namespace ZORG
{
namespace Crypto
{
namespace Impl
{

KeyExchangeFunction * CreateDH2k(Error& e, RNG * rng)
{
    return new(e) DHFunction(RFC3526::MODP2048, rng);
}

KeyExchangeFunction * CreateDH3k(Error& e, RNG * rng)
{
    return new(e) DHFunction(RFC3526::MODP3072, rng);
}

}
}
}

// EOF
