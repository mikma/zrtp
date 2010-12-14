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

#ifndef ZORG_CRYPTO_H_
#define ZORG_CRYPTO_H_

#include <zorg/zorg.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct Zorg_SASValue
{
    unsigned char data[4];
};

struct Zorg_SAS
{
    struct Zorg_Blob sas1;
    struct Zorg_Blob sas2;
    char b32buf_[4 + 1];
};

#ifdef __cplusplus
}
#endif

#if defined(__cplusplus) && !defined(ZORG_C_API)

#include <limits.h>

namespace ZORG
{
namespace Crypto
{

struct DHGroup
{
    Blob prime;
    Blob generator;
};

class RFC3526
{
private:
    RFC3526();

public:
    static const DHGroup Group5;
    static const DHGroup Group14;
    static const DHGroup Group15;
    static const DHGroup Group16;
    static const DHGroup Group17;
    static const DHGroup Group18;

    static const DHGroup& MODP1536;
    static const DHGroup& MODP2048;
    static const DHGroup& MODP3072;
    static const DHGroup& MODP4096;
    static const DHGroup& MODP6144;
    static const DHGroup& MODP8192;

public:
    static const DHGroup Group5_LE;
    static const DHGroup Group14_LE;
    static const DHGroup Group15_LE;
    static const DHGroup Group16_LE;
    static const DHGroup Group17_LE;
    static const DHGroup Group18_LE;

    static const DHGroup& MODP1536_LE;
    static const DHGroup& MODP2048_LE;
    static const DHGroup& MODP3072_LE;
    static const DHGroup& MODP4096_LE;
    static const DHGroup& MODP6144_LE;
    static const DHGroup& MODP8192_LE;
};

namespace RFC5764
{
    enum SRTPProfile
    {
	SRTP_UnknownProfile = -1,
        SRTP_AES128_CM_HMAC_SHA1_80 = 1,
        SRTP_AES128_CM_HMAC_SHA1_32 = 2,
        SRTP_AES256_CM_HMAC_SHA1_80 = 3, // DTLS-SRTP-03, not in RFC 5764
        SRTP_AES256_CM_HMAC_SHA1_32 = 4, // DTLS-SRTP-03, not in RFC 5764
        SRTP_NULL_HMAC_SHA1_80 = 5,
        SRTP_NULL_HMAC_SHA1_32 = 6
    };

    typedef EnumMask<SRTPProfile, SRTP_AES128_CM_HMAC_SHA1_80, SRTP_NULL_HMAC_SHA1_32> SRTPProfileMask;
};

class PGPWordList
{
private:
    PGPWordList();

public:
    static const Blob EvenWords[256];
    static const Blob OddWords[256];
};

class KeyExchange
{
public:
    virtual ~KeyExchange() {}
    virtual size_t getPublicKeyBits() = 0;
    virtual size_t getSharedSecretBits() = 0;
    virtual const Blob& getPublicKey(Error& e, Blob& publicKey) = 0;
    virtual const Blob& agree(Error& e, const Blob& peerPublicKey, Blob& sharedSecretKey) = 0;

    size_t getPublicKeyBytes() { return roundUpBitsToBytes(this->getPublicKeyBits()); }
    size_t getSharedSecretBytes() { return roundUpBitsToBytes(this->getSharedSecretBits()); }

    Blob getPublicKey(Error& e, const Blob& publicKey)
    {
	Blob tmp = publicKey;
	return this->getPublicKey(e, tmp);
    }

    Blob agree(Error& e, const Blob& peerPublicKey, const Blob& sharedSecretKey)
    {
	Blob tmp = sharedSecretKey;
	return this->agree(e, peerPublicKey, tmp);
    }
};

class KeyExchangeFunction
{
protected:
    void selfTestECP256(Error& e);
    void selfTestECP384(Error& e);
    void selfTestECP521(Error& e);

public:
    virtual ~KeyExchangeFunction() {}
    virtual void selfTest(Error& e) = 0;
    virtual size_t getPrivateKeyBits() = 0;
    virtual size_t getPublicKeyBits() = 0;
    virtual size_t getSharedSecretBits() = 0;
    virtual KeyExchange * Create(Error& e) = 0;
    virtual KeyExchange * Create(Error& e, const Blob& privateKey) = 0;

    size_t getPrivateKeyBytes() { return roundUpBitsToBytes(this->getPrivateKeyBits()); }
    size_t getPublicKeyBytes() { return roundUpBitsToBytes(this->getPublicKeyBits()); }
    size_t getSharedSecretBytes() { return roundUpBitsToBytes(this->getSharedSecretBits()); }
};

class Hash
{
public:
    virtual ~Hash() {}
    virtual void next(Error& e, const Blob& data) = 0;
    virtual const Blob& finish(Error& e, Blob& hashValue) = 0;

    const Blob finish(Error& e, const Blob& hashValue)
    {
	Blob tmp = hashValue;
	return this->finish(e, tmp);
    }
};

class HashFunction
{
protected:
    void selfTestSHA256(Error& e);
    void selfTestSHA384(Error& e);

public:
    virtual ~HashFunction() {}
    virtual void selfTest(Error& e) = 0;
    virtual size_t getHashBits() = 0;
    virtual Hash * Create(Error& e) = 0;
    virtual Hash * Create(Error& e, const Blob& key) = 0;

    const Blob& hash(Error& e, const Blob& data, Blob& hashValue)
    {
	Hash * hash = this->Create(e);

	if(hash)
	{
	    hash->next(e, data);
	    hash->finish(e, hashValue);
	    delete hash;
	}

	if(ZORG_FAILURE(e))
	    return NullBlob;

	return hashValue;
    }

    Blob hash(Error& e, const Blob& data, const Blob& hashValue)
    {
	Blob tmp = hashValue;
	return hash(e, data, tmp);
    }

    const Blob& mac(Error& e, const Blob& key, const Blob& data, Blob& macValue)
    {
	Hash * mac = this->Create(e, key);

	if(mac)
	{
	    mac->next(e, data);
	    mac->finish(e, macValue);
	    delete mac;
	}

	if(ZORG_FAILURE(e))
	    return NullBlob;

	return macValue;
    }

    Blob mac(Error& e, const Blob& key, const Blob& data, const Blob& macValue)
    {
	Blob tmp = macValue;
	return mac(e, key, data, tmp);
    }
};

class Cipher
{
public:
    virtual ~Cipher() {}
    virtual size_t getBlockBits() = 0;
    virtual const Blob& processBlock(Error& e, const Blob& input, Blob& output) = 0;

    const Blob& process(Error& e, const Blob& input, Blob& output);

    size_t getBlockBytes() { return roundUpBitsToBytes(this->getBlockBits()); }
    
    Blob processBlock(Error& e, const Blob& input, const Blob& output)
    {
	Blob tmp = output;
	return processBlock(e, input, tmp);
    }
    
    Blob process(Error& e, const Blob& input, const Blob& output)
    {
	Blob tmp = output;
	return process(e, input, tmp);
    }
};

class CipherFunction
{
protected:
    void selfTestAES128CFB(Error& e);
    void selfTestAES192CFB(Error& e);
    void selfTestAES256CFB(Error& e);
    void selfTestTwoFish128CFB(Error& e);
    void selfTestTwoFish192CFB(Error& e);
    void selfTestTwoFish256CFB(Error& e);

public:
    virtual ~CipherFunction() {}
    virtual void selfTest(Error& e) = 0;
    virtual size_t getBlockBits() = 0;
    virtual size_t getKeyBits() = 0;
    virtual Cipher * CreateEncryptorCFB(Error& e, const Blob& key, const Blob& iv) = 0;
    virtual Cipher * CreateDecryptorCFB(Error& e, const Blob& key, const Blob& iv) = 0;

    size_t getCFBIVBits() { return getBlockBits(); }

    size_t getBlockBytes() { return roundUpBitsToBytes(this->getBlockBits()); }
    size_t getKeyBytes() { return roundUpBitsToBytes(this->getKeyBits()); }
    size_t getCFBIVBytes() { return roundUpBitsToBytes(this->getCFBIVBits()); }
};

typedef ::Zorg_SAS SAS;
struct SASValue: public BitArray<32> {};

class SASFunction
{
public:
    virtual ~SASFunction() {}
    virtual const SAS& render(Error& e, const SASValue& sasValue, SAS& sas) = 0;
};

class RNG
{
public:
    virtual ~RNG() {}
    virtual void addEntropy(Error& e, const Blob& seed) = 0;
    virtual const Blob& generateRandom(Error& e, size_t nbyte, Blob& randbuf) = 0;

    Blob generateRandom(Error& e, size_t nbyte, const Blob& randbuf)
    {
	Blob tmp = randbuf;
	return generateRandom(e, nbyte, tmp);
    }

    const Blob& generateRandom(Error& e, Blob& randbuf)
    {
	return generateRandom(e, randbuf.dataSize, randbuf);
    }

    Blob generateRandom(Error& e, const Blob& randbuf)
    {
	Blob tmp = randbuf;
	return generateRandom(e, randbuf.dataSize, tmp);
    }
};

class RNGFunction
{
public:
    virtual ~RNGFunction() {}
    virtual RNG * Create(Error& e, const Blob& seed) = 0;
};

}
}

#endif

#endif

// EOF
