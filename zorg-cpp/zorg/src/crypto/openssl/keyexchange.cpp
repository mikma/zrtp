#include <zorg/zorg.h>
#include <zorg/crypto.h>
//#include <zorg/crypto/openssl.h>

#include <openssl/evp.h>
#include <openssl/dh.h>

namespace
{

class OpenSSLDHFunction: public ::ZORG::Crypto::KeyExchangeFunction
{
private:
    class OpenSSLDH: public ::ZORG::Crypto::KeyExchange
    {
    private:
        DH * m_dh;

    public:
        OpenSSLDH(::ZORG::Error& e, const ::ZORG::Crypto::DHGroup& group): m_dh(NULL)
        {
            if(ZORG_FAILURE(e))
                return;

            if((m_dh = DH_new()) == NULL) {
		ZORG_SET_ERROR(e, ::ZORG::ErrorInternal);
		return;
	    }

            m_dh->p = BN_new();
            if((m_dh->p = BN_bin2bn((const unsigned char *)group.prime.buffer, group.prime.dataSize, m_dh->p)) == NULL) {
		ZORG_SET_ERROR(e, ::ZORG::ErrorInternal);
		return;
	    }

            m_dh->g = BN_new();
            if((m_dh->g = BN_bin2bn((const unsigned char *)group.generator.buffer, group.generator.dataSize, m_dh->g)) == NULL) {
		ZORG_SET_ERROR(e, ::ZORG::ErrorInternal);
		return;
	    }

            DH_generate_key(m_dh); // FIXME: should use our RNG here
        }

        virtual ~OpenSSLDH()
        {
            if(m_dh)
                DH_free(m_dh);
        }

        virtual const ::ZORG::Blob& getPublicKey(::ZORG::Error& e, ::ZORG::Blob& publicKey)
        {
            if(ZORG_FAILURE(e))
                return ::ZORG::NullBlob;

            int publicKeySize = BN_num_bytes(m_dh->pub_key);
            if(publicKey.maxSize < publicKeySize) {
		ZORG_SET_ERROR(e, ::ZORG::ErrorKeySize);
		return ::ZORG::NullBlob;
	    }

            BN_bn2bin(m_dh->pub_key, (unsigned char *)publicKey.buffer);
            publicKey.dataSize = publicKeySize;
            return publicKey;
        }

        virtual const ::ZORG::Blob& agree(::ZORG::Error& e, const ::ZORG::Blob& peerPublicKey, ::ZORG::Blob& sharedSecretKey)
        {
            if(ZORG_FAILURE(e))
                return ::ZORG::NullBlob;

            int sharedKeySize = DH_size(m_dh);
            if(sharedSecretKey.maxSize < sharedKeySize) {
		ZORG_SET_ERROR(e, ::ZORG::ErrorKeySize);
		return ::ZORG::NullBlob;
	    }

	    BIGNUM * bnPeerPublicKey;
            if((bnPeerPublicKey = BN_new()) == NULL) {
		ZORG_SET_ERROR(e, ::ZORG::ErrorInternal);
		return ::ZORG::NullBlob;
	    }

            if((bnPeerPublicKey = BN_bin2bn((const unsigned char *)peerPublicKey.buffer, peerPublicKey.dataSize, bnPeerPublicKey)) == NULL) {
		ZORG_SET_ERROR(e, ::ZORG::ErrorInternal);
		return ::ZORG::NullBlob;
	    }

            if((sharedKeySize = DH_compute_key((unsigned char *)sharedSecretKey.buffer, bnPeerPublicKey, m_dh)) == 0) {
		ZORG_SET_ERROR(e, ::ZORG::ErrorInternal);
		return ::ZORG::NullBlob;
	    }

            sharedSecretKey.dataSize = sharedKeySize;

            BN_free(bnPeerPublicKey);

            return sharedSecretKey;
        }
    };

protected:
    OpenSSLDHFunction() {}
    virtual ~OpenSSLDHFunction() {}

    ::ZORG::Crypto::KeyExchange * Create(::ZORG::Error& e, const ::ZORG::Crypto::DHGroup& group)
    {
	return ::ZORG::guard_new(e, new(e) OpenSSLDH(e, group));
    }
};

class OpenSSLDH3072Function: public OpenSSLDHFunction
{
public:
    virtual ~OpenSSLDH3072Function() {}

    virtual size_t getPublicKeyBits()
    {
	return 3072;
    }

    virtual size_t getSharedSecretBits()
    {
	return 3072;
    }

    virtual ::ZORG::Crypto::KeyExchange * Create(::ZORG::Error& e)
    {
        return OpenSSLDHFunction::Create(e, ::ZORG::Crypto::RFC3526::MODP3072);
    }
};

}

namespace ZORG
{
namespace Crypto
{
namespace OpenSSL
{

KeyExchangeFunction * CreateDH3k(Error& e)
{
    return new(e) OpenSSLDH3072Function();
}

}
}
}

// EOF
