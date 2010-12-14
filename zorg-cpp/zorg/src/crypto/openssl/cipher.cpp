#include <zorg/zorg.h>
#include <zorg/crypto.h>

#include <openssl/evp.h>

namespace
{

class OpenSSLCipherFunction: public ::ZORG::Crypto::CipherFunction
{
private:
    class OpenSSLCipher: public ::ZORG::Crypto::Cipher
    {
    private:
        EVP_CIPHER_CTX m_ctx;
        bool m_encryptor;

    public:
        OpenSSLCipher(::ZORG::Error& e, bool encryptor, const EVP_CIPHER * cipher, const ::ZORG::Blob& key, const ::ZORG::Blob& iv): m_encryptor(encryptor)
        {
            EVP_CIPHER_CTX_init(&m_ctx);

            if(ZORG_FAILURE(e))
                return;

	    if(key.dataSize != m_ctx.key_len) { 
		ZORG_SET_ERROR(e, ::ZORG::ErrorKeySize);
		return;
	    }

		/***

	./src/crypto/openssl/cipher.cpp:31: error: ‘struct EVP_CIPHER_CTX’ has no member named ‘iv_len’

	    if(iv.dataSize != EVP_CIPHER_iv_length(&m_ctx)) {
		ZORG_SET_ERROR(e, ::ZORG::ErrorIVSize);
		return;
	    }
		***/

            if(!EVP_CipherInit_ex(&m_ctx, cipher, NULL, (const unsigned char *)key.buffer, (const unsigned char *)iv.buffer, !!m_encryptor)) 
		ZORG_SET_ERROR(e, ::ZORG::ErrorInternal);
        }

        virtual ~OpenSSLCipher()
        {
            EVP_CIPHER_CTX_cleanup(&m_ctx);
        }

        virtual const ::ZORG::Blob& processBlock(::ZORG::Error& e, const ::ZORG::Blob& input, ::ZORG::Blob& output)
        {
            if(ZORG_FAILURE(e)) return ::ZORG::NullBlob;

	    // TODO: what lenght must be checked ?
            int outl;
            if(!EVP_CipherUpdate(&m_ctx, (unsigned char *)output.buffer, &outl, (const unsigned char *)input.buffer, input.dataSize)) {
		ZORG_SET_ERROR(e, ::ZORG::ErrorInternal);
		return ::ZORG::NullBlob;
	    }

            output.dataSize = outl;
            return output;
        }

    };

protected:
    virtual ~OpenSSLCipherFunction() {}

    ::ZORG::Crypto::Cipher * CreateEncryptor(::ZORG::Error& e, const EVP_CIPHER * cipher, const ::ZORG::Blob& key)
    {
        return ::ZORG::guard_new(e, new(e) OpenSSLCipher(e, true, cipher, key, ::ZORG::NullBlob));
    }

    ::ZORG::Crypto::Cipher * CreateEncryptor(::ZORG::Error& e, const EVP_CIPHER * cipher, const ::ZORG::Blob& key, const ::ZORG::Blob& iv)
    {
        return ::ZORG::guard_new(e, new(e) OpenSSLCipher(e, true, cipher, key, iv));
    }

    ::ZORG::Crypto::Cipher * CreateDecryptor(::ZORG::Error& e, const EVP_CIPHER * cipher, const ::ZORG::Blob& key)
    {
        return ::ZORG::guard_new(e, new(e) OpenSSLCipher(e, false, cipher, key, ::ZORG::NullBlob));
    }

    ::ZORG::Crypto::Cipher * CreateDecryptor(::ZORG::Error& e, const EVP_CIPHER * cipher, const ::ZORG::Blob& key, const ::ZORG::Blob& iv)
    {
        return ::ZORG::guard_new(e, new(e) OpenSSLCipher(e, false, cipher, key, iv));
    }
};

class OpenSSLAES128: public OpenSSLCipherFunction
{
public:
    virtual ::ZORG::Crypto::Cipher * CreateEncryptorCFB(::ZORG::Error& e, const ::ZORG::Blob& key, const ::ZORG::Blob& iv)
    {
        return OpenSSLCipherFunction::CreateEncryptor(e, EVP_aes_128_cfb(), key, iv);
    }

    virtual ::ZORG::Crypto::Cipher * CreateDecryptorCFB(::ZORG::Error& e, const ::ZORG::Blob& key, const ::ZORG::Blob& iv)
    {
        return OpenSSLCipherFunction::CreateDecryptor(e, EVP_aes_128_cfb(), key, iv);
    }
};

}

// EOF
