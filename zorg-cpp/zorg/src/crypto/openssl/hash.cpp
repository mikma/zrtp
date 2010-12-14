#include <assert.h>
#include <stddef.h>
#include <algorithm>
#include <functional>
#include <memory>

#include <zorg/zorg.h>
#include <zorg/crypto.h>
#include <zorg/zrtp.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
/* problem, what if openssl don't support SHA 256 ? */
const EVP_MD *EVP_sha256(void);

namespace
{

class OpenSSLHashFunction: public ::ZORG::Crypto::HashFunction
{
private:
    class OpenSSLHash: public ::ZORG::Crypto::Hash
    {
    private:
        EVP_MD_CTX m_ctx;

    public:
        OpenSSLHash(::ZORG::Error& e, const EVP_MD * md)
        {
            EVP_MD_CTX_init(&m_ctx);

            if(ZORG_FAILURE(e))
                return;

            if(!EVP_DigestInit_ex(&m_ctx, md, NULL)) {
		ZORG_SET_ERROR(e, ::ZORG::ErrorInternal);
		return;
	    }
        }

        virtual ~OpenSSLHash()
        {
            EVP_MD_CTX_cleanup(&m_ctx);
        }

        virtual void next(::ZORG::Error& e, const ::ZORG::Blob& data)
        {
            if(!EVP_DigestUpdate(&m_ctx, data.buffer, data.dataSize))
		ZORG_SET_ERROR(e, ::ZORG::ErrorInternal);
        }

        virtual const ::ZORG::Blob& finish(::ZORG::Error& e, ::ZORG::Blob& hashValue)
        {
            if(hashValue.maxSize < m_ctx.digest->md_size) {
		ZORG_SET_ERROR(e, ::ZORG::ErrorBufferSize);
		return ::ZORG::NullBlob;
	    }

            unsigned int len;

            if(EVP_DigestFinal_ex(&m_ctx, (unsigned char *)hashValue.buffer, &len)) {
		ZORG_SET_ERROR(e, ::ZORG::ErrorInternal);
		return ::ZORG::NullBlob;
	    }

            hashValue.dataSize = len;
            return hashValue;
        }
    };

    class OpenSSLHMAC: public ::ZORG::Crypto::Hash
    {
    private:
        HMAC_CTX m_ctx;

    public:
        OpenSSLHMAC(::ZORG::Error& e, const EVP_MD * md, const ::ZORG::Blob& key)
        {
            HMAC_CTX_init(&m_ctx);

            if(ZORG_FAILURE(e))
                return;

            HMAC_Init_ex(&m_ctx, key.buffer, key.dataSize, md, NULL);
        }

        virtual ~OpenSSLHMAC()
        {
            HMAC_CTX_cleanup(&m_ctx);
        }

        virtual void next(::ZORG::Error& e, const ::ZORG::Blob& data)
        {
            /* if(! */HMAC_Update(&m_ctx, (const unsigned char *)data.buffer, data.dataSize) /*  ) 
		ZORG_SET_ERROR(e, ErrorInternal) */ ;
        }

        virtual const ::ZORG::Blob& finish(::ZORG::Error& e, ::ZORG::Blob& hashValue)
        {
            if(hashValue.maxSize < m_ctx.md->md_size) {
		ZORG_SET_ERROR(e, ::ZORG::ErrorBufferSize);
		return ::ZORG::NullBlob;
	    }

            unsigned int len;
            /* if(! */HMAC_Final(&m_ctx, (unsigned char *)hashValue.buffer, &len) /* ) {
		ZORG_SET_ERROR(e, ::ZORG::ErrorInternal);
		return ::ZORG::NullBlob */ ;
	    /* } */

            hashValue.dataSize = len;
            return hashValue;
        }
    };

protected:
    ::ZORG::Crypto::Hash * Create(::ZORG::Error& e, const EVP_MD * md)
    {
        return ::ZORG::guard_new (e, new(e) OpenSSLHash(e, md));
    }

    ::ZORG::Crypto::Hash * Create(::ZORG::Error& e, const EVP_MD * md, const ::ZORG::Blob& key)
    {
        return ::ZORG::guard_new (e, new(e) OpenSSLHMAC(e, md, key));
    }
};

class OpenSSLSha1: public OpenSSLHashFunction
{
public:
    virtual ~OpenSSLSha1() {}
    virtual ::ZORG::Crypto::Hash * Create(::ZORG::Error& e) { return OpenSSLHashFunction::Create(e, EVP_sha1()); }
    virtual ::ZORG::Crypto::Hash * Create(::ZORG::Error& e, const ::ZORG::Blob& key) { return OpenSSLHashFunction::Create(e, EVP_sha1(), key); }
};

class OpenSSLSha256: public OpenSSLHashFunction
{
public:
    virtual ~OpenSSLSha256() {}
    virtual ::ZORG::Crypto::Hash * Create(::ZORG::Error& e) { return OpenSSLHashFunction::Create(e, EVP_sha256()); }
    virtual ::ZORG::Crypto::Hash * Create(::ZORG::Error& e, const ::ZORG::Blob& key) { return OpenSSLHashFunction::Create(e, EVP_sha256(), key); }
};

}

// EOF
