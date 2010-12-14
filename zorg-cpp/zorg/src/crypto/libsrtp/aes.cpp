#include <assert.h>
#include <stdint.h>

#include <zorg/zorg.h>
#include <zorg/crypto.h>

extern "C"
{
#include <aes.h>
}

using namespace ::ZORG;
using namespace ::ZORG::Crypto;

class LibsrtpAES_CFB_Encryptor: public Cipher
{
private:
    aes_expanded_key_t m_key;
    BitArray<128> m_state;
    bool m_done;

    void updateState(const Blob& prevCipher)
    {
	assert(prevCipher.dataSize == sizeof(m_state));
	memcpy(&m_state, prevCipher.buffer, sizeof(m_state));
	aes_encrypt(reinterpret_cast<v128_t *>(&m_state), &m_key);
    }

public:
    LibsrtpAES_CFB_Encryptor(Error& e, const Blob& key, const Blob& iv): m_done(false)
    {
	if(ZORG_FAILURE(e))
	    return;

	if(key.dataSize != TemplateHell::RoundUpBitsToBytes<128>::value && key.dataSize != TemplateHell::RoundUpBitsToBytes<256>::value)
	{
	    ZORG_SET_ERROR(e, ErrorKeySize);
	    return;
	}

	if(iv.dataSize != sizeof(m_state))
	{
	    ZORG_SET_ERROR(e, ErrorIVSize);
	    return;
	}

	aes_expand_encryption_key(static_cast<uint8_t *>(key.buffer), key.dataSize, &m_key);
	updateState(iv);
    }

    virtual ~LibsrtpAES_CFB_Encryptor() {}

    virtual size_t getBlockBits()
    {
	return m_state.BITS;
    }

    virtual const Blob& processBlock(Error& e, const Blob& input, Blob& output)
    {
	if(ZORG_FAILURE(e))
	    return NullBlob;

	// FIXME: is this the correct handling of a partial block?
	if(m_done)
	{
	    ZORG_SET_ERROR(e, ErrorInternal);
	    return NullBlob;
	}

	if(input.dataSize > sizeof(m_state))
	{
	    ZORG_SET_ERROR(e, ErrorDataSize);
	    return NullBlob;
	}

	if(output.maxSize < input.dataSize)
	{
	    ZORG_SET_ERROR(e, ErrorBufferSize);
	    return NullBlob;
	}

	const uint8_t * inb = static_cast<uint8_t *>(input.buffer);
	uint8_t * outb = static_cast<uint8_t *>(output.buffer);

	for(size_t i = 0; i < input.dataSize; ++ i)
	    outb[i] = inb[i] ^ m_state.bytes[i];

        m_done = input.dataSize < sizeof(m_state);
	output.dataSize = input.dataSize;

	if(!m_done)
	    updateState(output);

	return output;
    }
};

class LibsrtpAES_CFB_Decryptor: public Cipher
{
private:
    aes_expanded_key_t m_key;
    BitArray<128> m_state;
    bool m_done;

    void updateState(const Blob& prevCipher)
    {
	assert(prevCipher.dataSize == sizeof(m_state));
	memcpy(&m_state, prevCipher.buffer, sizeof(m_state));
    }

public:
    LibsrtpAES_CFB_Decryptor(Error& e, const Blob& key, const Blob& iv): m_done(false)
    {
	if(ZORG_FAILURE(e))
	    return;

	if(key.dataSize != TemplateHell::RoundUpBitsToBytes<128>::value && key.dataSize != TemplateHell::RoundUpBitsToBytes<256>::value)
	{
	    ZORG_SET_ERROR(e, ErrorKeySize);
	    return;
	}

	if(iv.dataSize != sizeof(m_state))
	{
	    ZORG_SET_ERROR(e, ErrorIVSize);
	    return;
	}

	aes_expand_encryption_key(static_cast<uint8_t *>(key.buffer), key.dataSize, &m_key);
	updateState(iv);
    }

    virtual ~LibsrtpAES_CFB_Decryptor() {}

    virtual size_t getBlockBits()
    {
	return m_state.BITS;
    }

    virtual const Blob& processBlock(Error& e, const Blob& input, Blob& output)
    {
	if(ZORG_FAILURE(e))
	    return NullBlob;

	// FIXME: is this the correct handling of a partial block?
	if(m_done)
	{
	    ZORG_SET_ERROR(e, ErrorInternal);
	    return NullBlob;
	}

	if(input.dataSize > sizeof(m_state))
	{
	    ZORG_SET_ERROR(e, ErrorDataSize);
	    return NullBlob;
	}

	if(output.maxSize < input.dataSize)
	{
	    ZORG_SET_ERROR(e, ErrorBufferSize);
	    return NullBlob;
	}

	aes_encrypt(reinterpret_cast<v128_t *>(&m_state), &m_key);

	const uint8_t * inb = static_cast<uint8_t *>(input.buffer);
	uint8_t * outb = static_cast<uint8_t *>(output.buffer);

	for(size_t i = 0; i < input.dataSize; ++ i)
	    outb[i] = inb[i] ^ m_state.bytes[i];

        m_done = input.dataSize < sizeof(m_state);
	output.dataSize = input.dataSize;

	if(!m_done)
	    updateState(input);

	return output;
    }
};

class LibsrtpAES: public CipherFunction
{
private:
    size_t m_keyBits;

public:
    virtual void selfTest(Error& e)
    {
	if(ZORG_FAILURE(e))
	    return;

	switch(m_keyBits)
	{
	case 128:
	    selfTestAES128CFB(e);
	    break;

	case 192:
	    selfTestAES192CFB(e);
	    break;

	case 256:
	    selfTestAES256CFB(e);
	    break;

	default:
	    ZORG_UNREACHABLE_E(e);
	}
    }

    virtual size_t getKeyBits()
    {
	return m_keyBits;
    }

    virtual size_t getBlockBits()
    {
	return 128;
    }

    virtual Cipher * CreateEncryptorCFB(Error& e, const Blob& key, const Blob& iv)
    {
	return guard_new(e, new(e) LibsrtpAES_CFB_Encryptor(e, key, iv));
    }

    virtual Cipher * CreateDecryptorCFB(Error& e, const Blob& key, const Blob& iv)
    {
	return guard_new(e, new(e) LibsrtpAES_CFB_Decryptor(e, key, iv));
    }

    LibsrtpAES(size_t keyBits): m_keyBits(keyBits) {}
};

namespace ZORG
{
namespace Crypto
{
namespace Libsrtp
{

CipherFunction * CreateAES1(Error& e)
{
    return new(e) LibsrtpAES(128);
}

// NOTE: no AES-192 in libsrtp yet

CipherFunction * CreateAES3(Error& e)
{
    return new(e) LibsrtpAES(256);
}

}
}
}

// EOF
