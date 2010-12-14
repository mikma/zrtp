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

#include <assert.h>
#include <stddef.h>
#include <stdio.h>

#include <algorithm>
#include <functional>
#include <memory>

#include <zorg/zorg.h>
#include <zorg/srtp.h>
#include <zorg/zrtp.h>
#include <zorg/log.h>
#include <zorg/snprintf.h>

#include "crc32c.h"

namespace
{
static const char LOGC[] = "zrtp.cpp";
static const size_t LOGGING_CONTEXT_SIZE = 16 + 1;

bool ZORG_TEST_ABORT(::ZORG::Error& e)
{
    bool isAbort = ZORG_ERROR_CODE(e) == ::ZORG::ErrorInternalAbort;

    if(isAbort)
	ZORG_CLEAR_ERROR(e);

    return isAbort;
}

}

#define ZORG_DUMP_VARIABLE(E_, N_, X_) ((void)(ZORG_SUCCESS(E_) ? ((void)(ZORG_LOG(5,(LOGC, "%s:\n%s\n", (N_), ZORG_HEX_DUMP(X_))))) : ((void)0)))

using ZORG::Impl::zorg_snprintf;

namespace ZORG
{
namespace ZRTP
{

const Blob& KDF(::ZORG::Error& e, Crypto::HashFunction * hashFunction, const Blob& ki, const Blob& label, const Blob& context, uint32_t l, Blob& out)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    size_t outSize = l / CHAR_BIT + !!(l % CHAR_BIT);
    BitBlob<MAX_HASH_BITS> outBuffer;

    if(outSize > out.maxSize)
    {
	ZORG_SET_ERROR(e, ErrorBufferSize);
	return NullBlob;
    }

    std::auto_ptr<Crypto::Hash> hmac(hashFunction->Create(e, ki));

    if(ZORG_SUCCESS(e))
    {
	hmac->next(e, asBlob(int32_BE(1)));
	hmac->next(e, label);
	hmac->next(e, asBlob(byte(0)));
	hmac->next(e, context);
	hmac->next(e, asBlob(int32_BE(l)));
	hmac->finish(e, outBuffer);
	hmac.release();
    }

    Blob tmp;
    tmp.dataSize = 0;
    tmp.maxSize = outSize;
    tmp.buffer = out.buffer;

    truncatedCopy(e, outBuffer, tmp);

    if(ZORG_FAILURE(e))
	return NullBlob;

    out.dataSize = tmp.dataSize;
    return out;
}

const Blob& SASHash(::ZORG::Error& e, Crypto::HashFunction * hashFunction, const Blob& s0, const Blob& kdfContext, Blob& sasHash)
{
    return KDF(e, hashFunction, s0, asBlob("SAS"), kdfContext, 256, sasHash);
}

Crypto::SASValue SASValue(::ZORG::Error& e, const Blob& sasHash)
{
    Crypto::SASValue sasValue = Crypto::SASValue();

    if(ZORG_SUCCESS(e))
    {
        if(sasHash.dataSize < sizeof(sasValue.bytes))
	    ZORG_SET_ERROR(e, ErrorDataSize);
	else
	    memcpy(sasValue.bytes, sasHash.buffer, sizeof(sasValue.bytes));
    }

    return sasValue;
}

namespace Internal
{

const char * getSecurityEventName(SecurityEvent securityEvent)
{
    switch(securityEvent)
    {
    case SecurityEventError: return "ERROR";
    case SecurityEventCacheMismatch: return "CACHE_MISMATCH";
    case SecurityEventBadHelloHash: return "BAD_HELLO_HASH";
    case SecurityEventBadMessageMAC: return "BAD_MESSAGE_MAC";
    default: ZORG_UNREACHABLE(); return "<unknown>";
    }
}

const char * getEventName(Event event)
{
    switch(event)
    {
    case EventStop: return "STOP";
    case EventNoZRTP: return "NO_ZRTP";
    case EventClear: return "CLEAR";
    case EventSecure: return "SECURE";
    case EventDiscovery: return "DISCOVERY";
    case EventKeyAgreement: return "KEY_AGREEMENT";
    case EventConfirming: return "CONFIRMING";
    case EventLocalError: return "LOCAL_ERROR";
    default: ZORG_UNREACHABLE(); return "<unknown>";
    }
}

const char * getMessageTypeName(MessageType messageType)
{
    switch(messageType)
    {
    case MessageTypeNone: return "<SRTP media>";
    case MessageTypeHello: return "Hello";
    case MessageTypeHelloACK: return "HelloACK";
    case MessageTypeCommit: return "Commit";
    case MessageTypeDHPart1: return "DHPart1";
    case MessageTypeDHPart2: return "DHPart2";
    case MessageTypeConfirm1: return "Confirm1";
    case MessageTypeConfirm2: return "Confirm2";
    case MessageTypeConf2ACK: return "Conf2ACK";
    case MessageTypeError: return "Error";
    case MessageTypeErrorACK: return "ErrorACK";
    case MessageTypeGoClear: return "GoClear";
    case MessageTypeClearACK: return "ClearACK";
    case MessageTypeSASrelay: return "SASrelay";
    case MessageTypeRelayACK: return "RelayACK";
    case MessageTypePing: return "Ping";
    case MessageTypePingACK: return "PingACK";
    default: ZORG_UNREACHABLE(); return "<unknown>";
    }
}

using ::ZORG::asBlob;

struct MessageTypeBlock: public Words<2> {};

template<size_t Nbytes>
const MessageTypeBlock& asMessageTypeBlock(const char (& bytes)[Nbytes])
{
    return static_cast<const MessageTypeBlock&>(AsWords<2>(bytes));
}

template<size_t Nbytes>
const MessageTypeBlock& asMessageTypeBlock(const unsigned char (& bytes)[Nbytes])
{
    return static_cast<const MessageTypeBlock&>(AsWords<2>(bytes));
}

struct RawMessageBody
{
    BitArray<16> preamble;
    BitArray<16> length;
    MessageTypeBlock messageTypeBlock;
};

struct RawMessageHeader
{
    BitArray<16> header;
    BitArray<16> sequenceNumber;
    BitArray<32> magicCookie;
    SSRC ssrc;
};

template<class MessageBodyT>
struct RawMessage_T: public RawMessageHeader
{
    MessageBodyT body;
    // not pictured: crc
};

typedef RawMessage_T<RawMessageBody> RawMessage;

template<class BodyBufferT>
struct RawMessageFixedBuffer_T
{
private:
    RawMessageHeader m_header;
    BodyBufferT m_body;
    CRC m_crc;

public:
    Blob header() const { return rawObjectAsBlob(m_header); }
    
    Blob body() const { return rawObjectAsBlob(m_body); }
    
    const Blob& setBody(::ZORG::Error& e, const Blob& body)
    {
	if(ZORG_FAILURE(e))
	    return NullBlob;

	assert(body.buffer == this->body().buffer);
	assert(body.dataSize == this->body().dataSize);
	return body;
    }

    CRC& crc() { return m_crc; }
    const CRC& crc() const { return m_crc; }

    Blob data() const
    {
	Blob data;
	data.buffer = const_cast<RawMessageHeader *>(&m_header);
	data.dataSize = sizeof(m_header) + sizeof(m_body);
	data.maxSize = data.dataSize;
	return data;
    }
};

template<typename BodyBufferT>
Blob asBlob(const RawMessageFixedBuffer_T<BodyBufferT>& buffer)
{
    return rawObjectAsBlob(buffer);
}

template<class BodyBufferT>
struct RawMessageBodyBuffer_T
{
private:
    ByteArray<sizeof(BodyBufferT)> m_body;
    size_t m_bodySize;

public:
    RawMessageBodyBuffer_T(): m_bodySize(0) {}

    Blob body() const
    {
	Blob body = asBlob(m_body);
	body.dataSize = m_bodySize;
	return body;
    }

    const Blob& setBody(::ZORG::Error& e, const Blob& body)
    {
	if(ZORG_FAILURE(e))
	    return NullBlob;

	assert(body.buffer == this->body().buffer);
	assert(body.maxSize == this->body().maxSize);
	m_bodySize = body.dataSize;
	return body;
    }

    void copyBody(const Blob& body)
    {
	assert(body.dataSize <= this->body().maxSize);
	memcpy(&m_body, body.buffer, body.dataSize);
	m_bodySize = body.dataSize;
    }
};

template<class BodyBufferT> struct RawMessageBuffer_T;
template<typename BodyBufferT> Blob asBlob(const RawMessageBuffer_T<BodyBufferT>& buffer);

template<class BodyBufferT>
struct RawMessageBuffer_T
{
private:
    friend Blob asBlob<BodyBufferT>(const RawMessageBuffer_T<BodyBufferT>& buffer);

    RawMessageHeader m_header;
    ByteArray<sizeof(BodyBufferT)> m_body;
    ByteArray<sizeof(CRC)> m_crc;
    size_t m_bodySize;

public:
    RawMessageBuffer_T(): m_bodySize(0) {}

    Blob header() const { return rawObjectAsBlob(m_header); }
    
    Blob body() const
    {
	Blob body = asBlob(m_body);
	body.dataSize = m_bodySize;
	return body;
    }

    const Blob& setBody(::ZORG::Error& e, const Blob& body)
    {
	if(ZORG_FAILURE(e))
	    return NullBlob;

	assert(body.buffer == this->body().buffer);
	assert(body.dataSize <= this->body().maxSize);
	assert(body.maxSize == this->body().maxSize);
	m_bodySize = body.dataSize;
	return body;
    }

    CRC& crc() { return *reinterpret_cast<CRC *>(m_body.bytes + m_bodySize); }
    const CRC& crc() const { return *reinterpret_cast<const CRC *>(m_body.bytes + m_bodySize); }

    Blob data() const
    {
	Blob data;
	data.buffer = const_cast<RawMessageHeader *>(&m_header);
	data.dataSize = sizeof(m_header) + m_bodySize;
	data.maxSize = data.dataSize;
	return data;
    }
};

template<typename BodyBufferT>
Blob asBlob(const RawMessageBuffer_T<BodyBufferT>& buffer)
{
    Blob blob;
    blob.dataSize = sizeof(buffer.m_header) + buffer.m_bodySize + sizeof(buffer.m_crc);
    blob.maxSize = sizeof(buffer.m_header) + sizeof(buffer.m_body) + sizeof(buffer.m_crc);
    blob.buffer = const_cast<RawMessageHeader *>(&buffer.m_header);
    return blob;
}

static const size_t MIN_RAW_LENGTH = offsetof(RawMessage, body);
static const size_t MIN_MESSAGE_LENGTH = sizeof(RawMessage) + sizeof(CRC);
static const size_t MIN_MESSAGE_BODY_LENGTH = sizeof(RawMessageBody);

struct CookedMessage
{
    uint16_t sequenceNumber;
    SSRC ssrc;
    MessageType messageType;
    Blob messageBody;
};

MessageType cookMessage(::ZORG::Error& e, const char * LOGC, const Blob& rawMessageData, CookedMessage& cookedMessage)
{
    if(ZORG_FAILURE(e))
	return MessageTypeUnknown;

    // too short to be ZRTP
    if(rawMessageData.dataSize < MIN_RAW_LENGTH)
    {
	//ZORG_LOG(5,(LOGC, "message is too small to be ZRTP (%u bytes): assuming SRTP/SRTCP", rawMessageData.dataSize));
	cookedMessage.messageType = MessageTypeNone;
	return cookedMessage.messageType;
    }

    const RawMessage& rawMessage = *static_cast<RawMessage *>(rawMessageData.buffer);

    // not a ZRTP message, probably RTP, none of our business
    if(rawMessage.header != asBitArray<16>("\x10\x00") || rawMessage.magicCookie != asBitArray<32>("ZRTP"))
    {
	//ZORG_LOG(5,(LOGC, "message is not ZRTP: assuming SRTP/SRTCP"));
	cookedMessage.messageType = MessageTypeNone;
	return cookedMessage.messageType;
    }

    // corrupted ZRTP message
    if
    (
	// message must be composed of whole words
	rawMessageData.dataSize % WORD_BYTES != 0 ||
	// message must contain a header, minimal body and CRC
	rawMessageData.dataSize < MIN_MESSAGE_LENGTH
    )
    {
	ZORG_LOG(3,(LOGC, "message has invalid size (%u bytes): terminating", rawMessageData.dataSize));
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return MessageTypeUnknown;
    }

    // check CRC
    Blob rawCRCData;

    rawCRCData.dataSize = rawMessageData.dataSize - sizeof(CRC);
    rawCRCData.maxSize = rawMessageData.dataSize - sizeof(CRC);
    rawCRCData.buffer = rawMessageData.buffer;

    const CRC& rawCRC = *reinterpret_cast<CRC *>(static_cast<uint8_t *>(rawMessageData.buffer) + (rawMessageData.dataSize - sizeof(CRC)));
    BitArray<32> actualCRC = Impl::CRC32C(rawCRCData);

    // discard silently on CRC error
    if(actualCRC != rawCRC)
    {
	ZORG_LOG(4,(LOGC, "message has bad CRC (expected: %08X; actual: %08X): dropping", asInt32_BE(rawCRC), asInt32_BE(actualCRC)));
	return MessageTypeUnknown;
    }

    // message body must start with the specified preamble
    if(rawMessage.body.preamble != asBitArray<16>("\x50\x5a"))
    {
	ZORG_LOG(3,(LOGC, "message has bad preamble (expected: %04X; actual: %04X): terminating", asInt16_BE(asBitArray<16>("\x50\x5a")), asInt16_BE(rawMessage.body.preamble)));
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return MessageTypeUnknown;
    }

    // message body must fill the gap between header and CRC entirely
    size_t expectedBodyLength = rawMessageData.dataSize - (sizeof(RawMessageHeader) + sizeof(CRC));
    size_t actualBodyLength = asInt16_BE(rawMessage.body.length) * WORD_BYTES;

    if(actualBodyLength != expectedBodyLength)
    {
	ZORG_LOG(3,(LOGC, "message has bad body length (expected: %u; actual: %u): terminating", expectedBodyLength, actualBodyLength));
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return MessageTypeUnknown;
    }

    // try to parse the message type block
    if(rawMessage.body.messageTypeBlock == AsWords<2>("Hello   "))
	cookedMessage.messageType = MessageTypeHello;
    else if(rawMessage.body.messageTypeBlock == AsWords<2>("HelloACK"))
	cookedMessage.messageType = MessageTypeHelloACK;
    else if(rawMessage.body.messageTypeBlock == AsWords<2>("Commit  "))
	cookedMessage.messageType = MessageTypeCommit;
    else if(rawMessage.body.messageTypeBlock == AsWords<2>("DHPart1 "))
	cookedMessage.messageType = MessageTypeDHPart1;
    else if(rawMessage.body.messageTypeBlock == AsWords<2>("DHPart2 "))
	cookedMessage.messageType = MessageTypeDHPart2;
    else if(rawMessage.body.messageTypeBlock == AsWords<2>("Confirm1"))
	cookedMessage.messageType = MessageTypeConfirm1;
    else if(rawMessage.body.messageTypeBlock == AsWords<2>("Confirm2"))
	cookedMessage.messageType = MessageTypeConfirm2;
    else if(rawMessage.body.messageTypeBlock == AsWords<2>("Conf2ACK"))
	cookedMessage.messageType = MessageTypeConf2ACK;
    else if(rawMessage.body.messageTypeBlock == AsWords<2>("Error   "))
	cookedMessage.messageType = MessageTypeError;
    else if(rawMessage.body.messageTypeBlock == AsWords<2>("ErrorACK"))
	cookedMessage.messageType = MessageTypeErrorACK;
    else if(rawMessage.body.messageTypeBlock == AsWords<2>("GoClear "))
	cookedMessage.messageType = MessageTypeGoClear;
    else if(rawMessage.body.messageTypeBlock == AsWords<2>("ClearACK"))
	cookedMessage.messageType = MessageTypeClearACK;
    else if(rawMessage.body.messageTypeBlock == AsWords<2>("SASrelay"))
	cookedMessage.messageType = MessageTypeSASrelay;
    else if(rawMessage.body.messageTypeBlock == AsWords<2>("RelayACK"))
	cookedMessage.messageType = MessageTypeRelayACK;
    else if(rawMessage.body.messageTypeBlock == AsWords<2>("Ping    "))
	cookedMessage.messageType = MessageTypePing;
    else if(rawMessage.body.messageTypeBlock == AsWords<2>("PingACK "))
	cookedMessage.messageType = MessageTypePingACK;
    // unrecognized message type
    else
    {
	ZORG_LOG(3,(LOGC, "message has unknown type %s: terminating", ZORG_TEXT_DUMP(rawMessage.body.messageTypeBlock)));
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return MessageTypeUnknown;
    }

    // we're happy enough with this message
    cookedMessage.sequenceNumber = asInt16_BE(rawMessage.sequenceNumber);
    cookedMessage.ssrc = rawMessage.ssrc;
    cookedMessage.messageBody.dataSize = rawMessageData.dataSize - (sizeof(RawMessageHeader) + sizeof(CRC));
    cookedMessage.messageBody.maxSize = cookedMessage.messageBody.dataSize;
    cookedMessage.messageBody.buffer = const_cast<RawMessageBody *>(&rawMessage.body);

    return cookedMessage.messageType;
}

ProtocolVersion cookProtocolVersion(::ZORG::Error& e, const Word& rawVersion)
{
    if(ZORG_FAILURE(e))
	return ProtocolVersionUnknown;

    if(rawVersion == AsWord("1.10"))
	return ProtocolVersion1_10;
    else
	return ProtocolVersionUnsupported;
}

HashAlgorithm cookHashAlgorithm(::ZORG::Error& e, const char * LOGC, const Word& rawHashType)
{
    if(ZORG_FAILURE(e))
	return HashUnknown;

    if(rawHashType == AsWord("S256"))
	return HashS256;
    else if(rawHashType == AsWord("S384"))
	return HashS384;
    else if(rawHashType == AsWord("N256"))
	return HashN256;
    else if(rawHashType == AsWord("N384"))
	return HashN384;
    else
    {
	ZORG_LOG(3,(LOGC, "unknown hash type %s", ZORG_TEXT_DUMP(rawHashType)));
	ZORG_SET_ERROR(e, asErrorCode(ErrorHashTypeNotSupported));
	return HashUnknown;
    }
}

CipherAlgorithm cookCipherAlgorithm(::ZORG::Error& e, const char * LOGC, const Word& rawCipherType)
{
    if(ZORG_FAILURE(e))
	return CipherUnknown;

    if(rawCipherType == AsWord("AES1"))
	return CipherAES1;
    else if(rawCipherType == AsWord("AES2"))
	return CipherAES2;
    else if(rawCipherType == AsWord("AES3"))
	return CipherAES3;
    else if(rawCipherType == AsWord("2FS1"))
	return Cipher2FS1;
    else if(rawCipherType == AsWord("2FS2"))
	return Cipher2FS2;
    else if(rawCipherType == AsWord("2FS3"))
	return Cipher2FS3;
    else if(rawCipherType == AsWord("CAM1"))
	return CipherCAM1;
    else if(rawCipherType == AsWord("CAM2"))
	return CipherCAM2;
    else if(rawCipherType == AsWord("CAM3"))
	return CipherCAM3;
    else
    {
	ZORG_LOG(3,(LOGC, "unknown cipher type %s", ZORG_TEXT_DUMP(rawCipherType)));
	ZORG_SET_ERROR(e, asErrorCode(ErrorCipherTypeNotSupported));
	return CipherUnknown;
    }
}

AuthTagType cookAuthTagType(::ZORG::Error& e, const char * LOGC, const Word& rawAuthTagType)
{
    if(ZORG_FAILURE(e))
	return AuthTagUnknown;

    if(rawAuthTagType == AsWord("HS32"))
	return AuthTagHS32;
    else if(rawAuthTagType == AsWord("HS80"))
	return AuthTagHS80;
    else if(rawAuthTagType == AsWord("SK32"))
	return AuthTagSK32;
    else if(rawAuthTagType == AsWord("SK64"))
	return AuthTagSK64;
    else
    {
	ZORG_LOG(3,(LOGC, "unknown auth tag type %s", ZORG_TEXT_DUMP(rawAuthTagType)));
	ZORG_SET_ERROR(e, asErrorCode(ErrorSRTPAuthTagNotSupported));
	return AuthTagUnknown;
    }
}

KeyAgreementType cookKeyAgreementType(::ZORG::Error& e, const char * LOGC, const Word& rawKeyAgreementType)
{
    if(ZORG_FAILURE(e))
	return KeyAgreementUnknown;

    if(rawKeyAgreementType == AsWord("DH3k"))
	return KeyAgreementDH3k;
    else if(rawKeyAgreementType == AsWord("DH2k"))
	return KeyAgreementDH2k;
    else if(rawKeyAgreementType == AsWord("EC25"))
	return KeyAgreementEC25;
    else if(rawKeyAgreementType == AsWord("EC38"))
	return KeyAgreementEC38;
    else if(rawKeyAgreementType == AsWord("EC52"))
	return KeyAgreementEC52;
    else if(rawKeyAgreementType == AsWord("Prsh"))
	return KeyAgreementPrsh;
    else if(rawKeyAgreementType == AsWord("Mult"))
	return KeyAgreementMult;
    else
    {
	ZORG_LOG(3,(LOGC, "unknown key agreement type %s", ZORG_TEXT_DUMP(rawKeyAgreementType)));
	ZORG_SET_ERROR(e, asErrorCode(ErrorPublicKeyExchangeNotSupported));
	return KeyAgreementUnknown;
    }
}

SASType cookSASType(::ZORG::Error& e, const char * LOGC, const Word& rawSASType)
{
    if(ZORG_FAILURE(e))
	return SASUnknown;

    if(rawSASType == AsWord("B32 "))
	return SASB32;
    else if(rawSASType == AsWord("B256"))
	return SASB256;
    else
    {
	ZORG_LOG(3,(LOGC, "unknown SAS scheme %s", ZORG_TEXT_DUMP(rawSASType)));
	ZORG_SET_ERROR(e, asErrorCode(ErrorSASSchemeNotSupported));
	return SASUnknown;
    }
}

template<class CookedT>
const CookedT& cookEmptyMessage(::ZORG::Error& e, const char * LOGC, const Blob& rawData, CookedT& cooked, MessageType messageType)
{
    if(ZORG_FAILURE(e))
	return cooked;

    if(rawData.dataSize != sizeof(RawMessageBody))
    {
	ZORG_LOG(3,(LOGC, "message has bad body length (expected: %u; actual: %u): terminating", sizeof(RawMessageBody), rawData.dataSize));
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return cooked;
    }

    // message is good, cook it
    cooked.type = messageType;

    return cooked;
}

struct RawHello: public RawMessageBody
{
    Word version;
    Words<4> clientId;
    Words<8> h3;
    ZID zid;
    Word flagsAndProfileSize;
    // not pictured: profile, mac
};

const Hello& cookHello(::ZORG::Error& e, const char * LOGC, const Blob& rawHelloData, Hello& cookedHello)
{
    if(ZORG_FAILURE(e))
	return cookedHello;

    if(rawHelloData.dataSize < sizeof(RawHello))
    {
	ZORG_LOG(3,(LOGC, "message has bad body length (expected: >= %u; actual: %u): terminating", sizeof(RawHello), rawHelloData.dataSize));
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return cookedHello;
    }

    const RawHello& rawHello = *static_cast<RawHello *>(rawHelloData.buffer);

    // check protocol version before anything else
    ProtocolVersion version = cookProtocolVersion(e, rawHello.version);

    if(ZORG_FAILURE(e))
	return cookedHello;

    if(version != ProtocolVersion1_10)
    {
	ZORG_LOG(3,(LOGC, "message has unknown or unsupported version %s: terminating", ZORG_TEXT_DUMP(rawHello.version)));
	ZORG_SET_ERROR(e, asErrorCode(ErrorUnsupportedZRTPVersion));
	return cookedHello;
    }

    // ensure no undefined flags are set
    if((rawHello.flagsAndProfileSize.bytes[0] & 0x8F) != 0 || (rawHello.flagsAndProfileSize.bytes[1] & 0xF0) != 0)
    {
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return cookedHello;
    }

    // calculate profile size
    unsigned hc = (rawHello.flagsAndProfileSize.bytes[1] >> 0) & 0xf;
    unsigned cc = (rawHello.flagsAndProfileSize.bytes[2] >> 4) & 0xf;
    unsigned ac = (rawHello.flagsAndProfileSize.bytes[2] >> 0) & 0xf;
    unsigned kc = (rawHello.flagsAndProfileSize.bytes[3] >> 4) & 0xf;
    unsigned sc = (rawHello.flagsAndProfileSize.bytes[3] >> 0) & 0xf;

    // Hello message too short
    size_t expectedBodyLength = sizeof(RawHello)/* fixed-size part */ + (hc + cc + ac + kc + sc) * WORD_BYTES/* profile */ + sizeof(Words<2>)/* 2-word MAC */;

    if(rawHelloData.dataSize != expectedBodyLength)
    {
	ZORG_LOG(3,(LOGC, "message has bad body length (expected: %u; actual: %u): terminating", expectedBodyLength, rawHelloData.dataSize));
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return cookedHello;
    }

    const Word * profile = reinterpret_cast<const Word *>(&rawHello + 1);

    // hash algorithms
    const Word * rawHashAlgorithms = profile;
    HashAlgorithmList hashAlgorithms;

    for(unsigned i = 0; i < hc; ++ i)
    {
	HashAlgorithm hashAlgorithm = cookHashAlgorithm(e, LOGC, rawHashAlgorithms[i]);

	if(ZORG_FAILURE(e))
	    return cookedHello;

	hashAlgorithms += hashAlgorithm;
    }

    // cipher algorithms
    const Word * rawCipherAlgorithms = rawHashAlgorithms + hc;
    CipherAlgorithmList cipherAlgorithms;

    for(unsigned i = 0; i < cc; ++ i)
    {
	CipherAlgorithm cipherAlgorithm = cookCipherAlgorithm(e, LOGC, rawCipherAlgorithms[i]);

	if(ZORG_FAILURE(e))
	    return cookedHello;

	cipherAlgorithms += cipherAlgorithm;
    }

    // auth tag types
    const Word * rawAuthTagTypes = rawCipherAlgorithms + cc;
    AuthTagTypeList authTagTypes;

    for(unsigned i = 0; i < ac; ++ i)
    {
	AuthTagType authTagType = cookAuthTagType(e, LOGC, rawAuthTagTypes[i]);

	if(ZORG_FAILURE(e))
	    return cookedHello;

	authTagTypes += authTagType;
    }

    // key agreement types
    const Word * rawKeyAgreementTypes = rawAuthTagTypes + ac;
    KeyAgreementTypeList keyAgreementTypes;

    for(unsigned i = 0; i < kc; ++ i)
    {
	KeyAgreementType keyAgreementType = cookKeyAgreementType(e, LOGC, rawKeyAgreementTypes[i]);

	if(ZORG_FAILURE(e))
	    return cookedHello;

	keyAgreementTypes += keyAgreementType;
    }

    // SAS types
    const Word * rawSASTypes = rawKeyAgreementTypes + kc;
    SASTypeList sasTypes;

    for(unsigned i = 0; i < sc; ++ i)
    {
	SASType sasType = cookSASType(e, LOGC, rawSASTypes[i]);

	if(ZORG_FAILURE(e))
	    return cookedHello;

	sasTypes += sasType;
    }

    const Words<2>& mac = *reinterpret_cast<const Words<2> *>(rawSASTypes + sc);

    // message is good, cook it
    cookedHello.type = MessageTypeHello;
    cookedHello.version = version;
    memcpy(cookedHello.clientId, rawHello.clientId.bytes, sizeof(rawHello.clientId.bytes));
    cookedHello.clientId[sizeof(rawHello.clientId.bytes)] = 0;
    cookedHello.h3 = rawHello.h3;
    cookedHello.zid = rawHello.zid;
    cookedHello.streamFlags.signatureCapable = !!(rawHello.flagsAndProfileSize.bytes[0] & 0x40);
    cookedHello.streamFlags.mitm = !!(rawHello.flagsAndProfileSize.bytes[0] & 0x20);
    cookedHello.streamFlags.passive = !!(rawHello.flagsAndProfileSize.bytes[0] & 0x10);
    cookedHello.hashAlgorithms = hashAlgorithms;
    cookedHello.cipherAlgorithms = cipherAlgorithms;
    cookedHello.authTagTypes = authTagTypes;
    cookedHello.keyAgreementTypes = keyAgreementTypes;
    cookedHello.sasTypes = sasTypes;
    cookedHello.mac = mac;

    return cookedHello;
}

struct RawHelloACK: public RawMessageBody {};

const HelloACK& cookHelloACK(::ZORG::Error& e, const char * LOGC, const Blob& rawHelloACKData, HelloACK& cookedHelloACK)
{
    return cookEmptyMessage(e, LOGC, rawHelloACKData, cookedHelloACK, MessageTypeHelloACK);
}

struct RawCommit: public RawMessageBody
{
    Words<8> h2;
    ZID zid;
    Word hashAlgorithm;
    Word cipherAlgorithm;
    Word authTagType;
    Word keyAgreementType;
    Word sasType;
};

struct RawCommitDH: public RawCommit
{
    Words<8> hvi;
    Words<2> mac;
};

struct RawCommitMult: public RawCommit
{
    Words<4> nonce;
    Words<2> mac;
};

struct RawCommitPrsh: public RawCommit
{
    Words<4> nonce;
    Words<2> keyID;
    Words<2> mac;
};

const Commit& cookCommit(::ZORG::Error& e, const char * LOGC, const Blob& rawCommitData, Commit& cookedCommit)
{
    if(ZORG_FAILURE(e))
	return cookedCommit;

    if(rawCommitData.dataSize < sizeof(RawCommit))
    {
	ZORG_LOG(3,(LOGC, "message has bad body length (expected: >= %u; actual: %u): terminating", sizeof(RawCommit), rawCommitData.dataSize));
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return cookedCommit;
    }

    const RawCommit& rawCommit = *static_cast<RawCommit *>(rawCommitData.buffer);

    KeyAgreementType keyAgreementType = cookKeyAgreementType(e, LOGC, rawCommit.keyAgreementType);

    if(ZORG_FAILURE(e))
	return cookedCommit;

    switch(keyAgreementType)
    {
    default:
	if(rawCommitData.dataSize != sizeof(RawCommitDH))
	{
	    ZORG_LOG(3,(LOGC, "message has bad body length (expected: %u; actual: %u): terminating", sizeof(RawCommitDH), rawCommitData.dataSize));
	    ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	    return cookedCommit;
	}

	break;

    case KeyAgreementMult:
	if(rawCommitData.dataSize != sizeof(RawCommitMult))
	{
	    ZORG_LOG(3,(LOGC, "message has bad body length (expected: %u; actual: %u): terminating", sizeof(RawCommitMult), rawCommitData.dataSize));
	    ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	    return cookedCommit;
	}

	break;

    case KeyAgreementPrsh:
	if(rawCommitData.dataSize != sizeof(RawCommitPrsh))
	{
	    ZORG_LOG(3,(LOGC, "message has bad body length (expected: %u; actual: %u): terminating", sizeof(RawCommitPrsh), rawCommitData.dataSize));
    	    ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	    return cookedCommit;
	}

	break;

    case KeyAgreementUnknown:
	ZORG_UNREACHABLE_E(e);
	return cookedCommit;
    }

    HashAlgorithm hashAlgorithm = cookHashAlgorithm(e, LOGC, rawCommit.hashAlgorithm);
    CipherAlgorithm cipherAlgorithm = cookCipherAlgorithm(e, LOGC, rawCommit.cipherAlgorithm);
    AuthTagType authTagType = cookAuthTagType(e, LOGC, rawCommit.authTagType);
    SASType sasType = cookSASType(e, LOGC, rawCommit.sasType);

    if(ZORG_FAILURE(e))
	return cookedCommit;

    // message is good, cook it
    cookedCommit.type = MessageTypeCommit;
    cookedCommit.h2 = rawCommit.h2;
    cookedCommit.zid = rawCommit.zid;
    cookedCommit.hashAlgorithm = hashAlgorithm;
    cookedCommit.cipherAlgorithm = cipherAlgorithm;
    cookedCommit.authTagType = authTagType;
    cookedCommit.keyAgreementType = keyAgreementType;
    cookedCommit.sasType = sasType;

    switch(keyAgreementType)
    {
    default:
	{
	    const RawCommitDH& rawCommitDH = static_cast<const RawCommitDH&>(rawCommit);
	    cookedCommit.kaparam.dh.hvi = rawCommitDH.hvi;
	    cookedCommit.mac = rawCommitDH.mac;
	}

	break;

    case KeyAgreementMult:
	{
	    const RawCommitMult& rawCommitMult = static_cast<const RawCommitMult&>(rawCommit);
	    cookedCommit.kaparam.mult.nonce = rawCommitMult.nonce;
	    cookedCommit.mac = rawCommitMult.mac;
	}

	break;

    case KeyAgreementPrsh:
	{
	    const RawCommitPrsh& rawCommitPrsh = static_cast<const RawCommitPrsh&>(rawCommit);
	    cookedCommit.kaparam.prsh.nonce = rawCommitPrsh.nonce;
	    cookedCommit.kaparam.prsh.keyID = rawCommitPrsh.keyID;
	    cookedCommit.mac = rawCommitPrsh.mac;
	}

	break;

    case KeyAgreementUnknown:
	ZORG_UNREACHABLE_E(e);
	return cookedCommit;
    }

    return cookedCommit;
}

size_t getPVWords(::ZORG::Error& e, KeyAgreementType keyAgreementType)
{
    if(ZORG_FAILURE(e))
	return 0;

    switch(keyAgreementType)
    {
    case KeyAgreementDH3k: return 96;
    case KeyAgreementDH2k: return 64;
    case KeyAgreementEC25: return 16;
    case KeyAgreementEC38: return 24;
    case KeyAgreementEC52: return 33;

    default:
	break;
    }

    ZORG_UNREACHABLE_E(e);
    return 0;
}

size_t getPVSize(::ZORG::Error& e, KeyAgreementType keyAgreementType)
{
    return getPVWords(e, keyAgreementType) * WORD_BYTES;
}

size_t getDHResultSize(::ZORG::Error& e, KeyAgreementType keyAgreementType)
{
    if(ZORG_FAILURE(e))
	return 0;

    switch(keyAgreementType)
    {
    case KeyAgreementDH3k: return 384;
    case KeyAgreementDH2k: return 256;
    case KeyAgreementEC25: return 32;
    case KeyAgreementEC38: return 48;
    case KeyAgreementEC52: return 66;

    default:
	break;
    }

    ZORG_UNREACHABLE_E(e);
    return 0;
}

struct RawDHPart1: public RawMessageBody
{
    Words<8> h1;
    Words<2> rs1IDr;
    Words<2> rs2IDr;
    Words<2> auxsecretIDr;
    Words<2> pbxsecretIDr;
    // not pictured: pvr, MAC
};

const DHPart1& cookDHPart1(::ZORG::Error& e, const char * LOGC, const Blob& rawDHPart1Data, KeyAgreementType keyAgreementType, DHPart1& cookedDHPart1)
{
    if(ZORG_FAILURE(e))
	return cookedDHPart1;

    size_t pvrSize = getPVSize(e, keyAgreementType);

    if(ZORG_FAILURE(e))
	return cookedDHPart1;

    size_t expectedMinBodyLength = sizeof(RawDHPart1) + pvrSize + sizeof(Words<2>);

    if(rawDHPart1Data.dataSize < expectedMinBodyLength)
    {
	ZORG_LOG(3,(LOGC, "message has bad body length (expected: >= %u; actual: %u): terminating", expectedMinBodyLength, rawDHPart1Data.dataSize));
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return cookedDHPart1;
    }

    const RawDHPart1& rawDHPart1 = *static_cast<RawDHPart1 *>(rawDHPart1Data.buffer);
    const uint8_t * rawPvr = static_cast<uint8_t *>(rawDHPart1Data.buffer) + sizeof(RawDHPart1);
    const Words<2>& rawMAC = *reinterpret_cast<Words<2> *>(static_cast<uint8_t *>(rawDHPart1Data.buffer) + sizeof(RawDHPart1) + pvrSize);

    // message is good, cook it
    cookedDHPart1.type = MessageTypeDHPart1;
    cookedDHPart1.h1 = rawDHPart1.h1;
    cookedDHPart1.rs1IDr = rawDHPart1.rs1IDr;
    cookedDHPart1.rs2IDr = rawDHPart1.rs2IDr;
    cookedDHPart1.auxsecretIDr = rawDHPart1.auxsecretIDr;
    cookedDHPart1.pbxsecretIDr = rawDHPart1.pbxsecretIDr;
    memcpy(cookedDHPart1.pvr.bytes, rawPvr, pvrSize);
    cookedDHPart1.pvr.dataSize = pvrSize;
    cookedDHPart1.mac = rawMAC;

    return cookedDHPart1;
}

struct RawDHPart2: public RawMessageBody
{
    Words<8> h1;
    Words<2> rs1IDi;
    Words<2> rs2IDi;
    Words<2> auxsecretIDi;
    Words<2> pbxsecretIDi;
    // not pictured: pvi, MAC
};

const DHPart2& cookDHPart2(::ZORG::Error& e, const char * LOGC, const Blob& rawDHPart2Data, KeyAgreementType keyAgreementType, DHPart2& cookedDHPart2)
{
    if(ZORG_FAILURE(e))
	return cookedDHPart2;

    size_t pviSize = getPVSize(e, keyAgreementType);

    if(ZORG_FAILURE(e))
	return cookedDHPart2;

    size_t expectedMinBodyLength = sizeof(RawDHPart2) + pviSize + sizeof(Words<2>);

    if(rawDHPart2Data.dataSize < expectedMinBodyLength)
    {
	ZORG_LOG(3,(LOGC, "message has bad body length (expected: >= %u; actual: %u): terminating", expectedMinBodyLength, rawDHPart2Data.dataSize));
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return cookedDHPart2;
    }

    const RawDHPart2& rawDHPart2 = *static_cast<RawDHPart2 *>(rawDHPart2Data.buffer);
    const uint8_t * rawPvi = static_cast<uint8_t *>(rawDHPart2Data.buffer) + sizeof(RawDHPart2);
    const Words<2>& rawMAC = *reinterpret_cast<Words<2> *>(static_cast<uint8_t *>(rawDHPart2Data.buffer) + sizeof(RawDHPart2) + pviSize);

    // message is good, cook it
    cookedDHPart2.type = MessageTypeDHPart2;
    cookedDHPart2.h1 = rawDHPart2.h1;
    cookedDHPart2.rs1IDi = rawDHPart2.rs1IDi;
    cookedDHPart2.rs2IDi = rawDHPart2.rs2IDi;
    cookedDHPart2.auxsecretIDi = rawDHPart2.auxsecretIDi;
    cookedDHPart2.pbxsecretIDi = rawDHPart2.pbxsecretIDi;
    memcpy(cookedDHPart2.pvi.bytes, rawPvi, pviSize);
    cookedDHPart2.pvi.dataSize = pviSize;
    cookedDHPart2.mac = rawMAC;

    return cookedDHPart2;
}

struct RawConfirmEncryptedPart
{
    Words<8> h0;
    Word sigLenAndFlags;
    Word cacheExpirationInterval;
    // TBD: signature
};

struct RawConfirm: public RawMessageBody
{
    Words<2> confirmMAC;
    Words<4> cfbIV;
    RawConfirmEncryptedPart encrypted;
};

typedef RawConfirm RawConfirm1, RawConfirm2;

const Blob& decryptCFB(::ZORG::Error& e, Crypto::CipherFunction * cipherFunction, const Blob& key, const Blob& iv, const Blob& encrypted, Blob& decrypted)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    if(decrypted.maxSize < encrypted.dataSize)
    {
	ZORG_SET_ERROR(e, ErrorBufferSize);
	return NullBlob;
    }

    size_t cipherBlockBits = cipherFunction->getBlockBits();
    assert(cipherBlockBits % CHAR_BIT == 0);
    assert(cipherBlockBits <= MAX_CIPHER_BLOCK_BITS);

    size_t cipherBlockBytes = cipherBlockBits / CHAR_BIT;

    Blob actualKey = key;
    assert(actualKey.dataSize >= cipherFunction->getKeyBytes());
    actualKey.dataSize = cipherFunction->getKeyBytes();

    Blob actualIV = iv;
    assert(actualIV.dataSize >= cipherFunction->getCFBIVBytes());
    actualIV.dataSize = cipherFunction->getCFBIVBytes();

    std::auto_ptr<Crypto::Cipher> decryptor(cipherFunction->CreateDecryptorCFB(e, actualKey, actualIV));

    if(ZORG_FAILURE(e))
	return NullBlob;

    unsigned char * in = static_cast<unsigned char *>(encrypted.buffer);
    unsigned char * out = static_cast<unsigned char *>(decrypted.buffer);

    size_t inSize = encrypted.dataSize;

    Blob inBlock;
    inBlock.dataSize = cipherBlockBytes;
    inBlock.maxSize = cipherBlockBytes;

    Blob outBlock;
    outBlock.dataSize = cipherBlockBytes;
    outBlock.maxSize = cipherBlockBytes;

    for(; inSize >= cipherBlockBytes; inSize -= cipherBlockBytes, in += cipherBlockBytes, out += cipherBlockBytes)
    {
	inBlock.buffer = in;
	outBlock.buffer = out;

	decryptor->processBlock(e, inBlock, outBlock);

	assert(outBlock.dataSize == outBlock.maxSize);
	assert(outBlock.dataSize == cipherBlockBytes);
    }

    if(inSize)
    {
	inBlock.dataSize = inSize;
	inBlock.buffer = in;

	outBlock.buffer = out;

	decryptor->processBlock(e, inBlock, outBlock);

	assert(outBlock.dataSize == inSize);
    }

    decrypted.dataSize = encrypted.dataSize;
    return decrypted;
}

Blob decryptCFB(::ZORG::Error& e, Crypto::CipherFunction * cipherFunction, const Blob& key, const Blob& iv, const Blob& encrypted, const Blob& decrypted)
{
    Blob tmp = decrypted;
    return decryptCFB(e, cipherFunction, key, iv, encrypted, tmp);
}

const Confirm& cookConfirm(::ZORG::Error& e, const char * LOGC, const Blob& rawConfirmData, Crypto::HashFunction * sessionHash, const Blob& mackey, Crypto::CipherFunction * sessionCipher, const Blob& zrtpkey, MessageType messageType, Confirm& cookedConfirm)
{
    if(ZORG_FAILURE(e))
	return cookedConfirm;

    // TBD: this size check assumes no signature support
    if(rawConfirmData.dataSize != sizeof(RawConfirm))
    {
	ZORG_LOG(3,(LOGC, "message has bad body length (expected: %u; actual: %u): terminating", sizeof(RawConfirm), rawConfirmData.dataSize));
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return cookedConfirm;
    }

    const RawConfirm& rawConfirm = *static_cast<RawConfirm *>(rawConfirmData.buffer);

    BitBlob<MAX_MAC_BITS> macValue;
    sessionHash->mac(e, mackey, rawObjectAsBlob(rawConfirm.encrypted), macValue);

    if(ZORG_FAILURE(e))
	return cookedConfirm;

    if(AsWords<2>(macValue.bytes) != rawConfirm.confirmMAC)
    {
	ZORG_SET_ERROR(e, asErrorCode(ErrorBadConfirmMAC));
	return cookedConfirm;
    }

    RawConfirmEncryptedPart decrypted;
    decryptCFB(e, sessionCipher, zrtpkey, asBlob(rawConfirm.cfbIV), rawObjectAsBlob(rawConfirm.encrypted), rawObjectAsBlob(decrypted));

    // TBD: validate signature length

    if
    (
	decrypted.sigLenAndFlags.bytes[0] ||
	decrypted.sigLenAndFlags.bytes[1] ||
	decrypted.sigLenAndFlags.bytes[2] ||
	decrypted.sigLenAndFlags.bytes[3] & 0xf0
    )
    {
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return cookedConfirm;
    }

    // message is good, cook it
    cookedConfirm.type = messageType;
    cookedConfirm.confirmMAC = rawConfirm.confirmMAC;
    cookedConfirm.cfbIV = rawConfirm.cfbIV;
    cookedConfirm.h0 = decrypted.h0;
    cookedConfirm.pbxEnrollment = !!(decrypted.sigLenAndFlags.bytes[3] & 0x08);
    cookedConfirm.sasVerified = !!(decrypted.sigLenAndFlags.bytes[3] & 0x04);
    cookedConfirm.allowClear = !!(decrypted.sigLenAndFlags.bytes[3] & 0x02);
    cookedConfirm.disclosure = !!(decrypted.sigLenAndFlags.bytes[3] & 0x01);
    cookedConfirm.cacheExpirationInterval = asInt32_BE(decrypted.cacheExpirationInterval);

    return cookedConfirm;
}

const Confirm1& cookConfirm1(::ZORG::Error& e, const char * LOGC, const Blob& rawConfirm1Data, Crypto::HashFunction * sessionHash, const Blob& mackeyr, Crypto::CipherFunction * sessionCipher, const Blob& zrtpkeyr, Confirm1& cookedConfirm1)
{
    return cookConfirm(e, LOGC, rawConfirm1Data, sessionHash, mackeyr, sessionCipher, zrtpkeyr, MessageTypeConfirm1, cookedConfirm1);
}

const Confirm2& cookConfirm2(::ZORG::Error& e, const char * LOGC, const Blob& rawConfirm2Data, Crypto::HashFunction * sessionHash, const Blob& mackeyi, Crypto::CipherFunction * sessionCipher, const Blob& zrtpkeyi, Confirm2& cookedConfirm2)
{
    return cookConfirm(e, LOGC, rawConfirm2Data, sessionHash, mackeyi, sessionCipher, zrtpkeyi, MessageTypeConfirm2, cookedConfirm2);
}

struct RawConf2ACK: public RawMessageBody {};

const Conf2ACK& cookConf2ACK(::ZORG::Error& e, const char * LOGC, const Blob& rawConf2ACKData, Conf2ACK& cookedConf2ACK)
{
    return cookEmptyMessage(e, LOGC, rawConf2ACKData, cookedConf2ACK, MessageTypeConf2ACK);
}

struct RawError: public RawMessageBody
{
    Word errorCode;
};

const Error& cookError(::ZORG::Error& e, const char * LOGC, const Blob& rawErrorData, Error& cookedError)
{
    if(ZORG_FAILURE(e))
	return cookedError;

    if(rawErrorData.dataSize != sizeof(RawError))
    {
	ZORG_LOG(3,(LOGC, "message has bad body length (expected: %u; actual: %u): terminating", sizeof(RawError), rawErrorData.dataSize));
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return cookedError;
    }

    const RawError& rawError = *static_cast<RawError *>(rawErrorData.buffer);
    uint32_t rawErrorCode = asInt32_BE(rawError.errorCode);

    // message is good, cook it
    cookedError.type = MessageTypeError;

    switch(rawErrorCode)
    {
    case ErrorMalformedPacket:
    case ErrorCriticalSoftwareError:
    case ErrorUnsupportedZRTPVersion:
    case ErrorHelloComponentsMismatch:
    case ErrorHashTypeNotSupported:
    case ErrorCipherTypeNotSupported:
    case ErrorPublicKeyExchangeNotSupported:
    case ErrorSRTPAuthTagNotSupported:
    case ErrorSASSchemeNotSupported:
    case ErrorNoSharedSecret:
    case ErrorDHBadPV:
    case ErrorDHHVIMismatch:
    case ErrorUntrustedMitm:
    case ErrorBadConfirmMAC:
    case ErrorNonceReuse:
    case ErrorZIDCollision:
    case ErrorSSRCCollision:
    case ErrorServiceUnavailable:
    case ErrorProtocolTimeout:
    case ErrorGoClearDisallowed:
        cookedError.errorCode = static_cast<ErrorCode>(rawErrorCode);
	break;

    default:
	cookedError.errorCode = ErrorUnknown;
	break;
    }

    return cookedError;
}

struct RawErrorACK: public RawMessageBody {};

const ErrorACK& cookErrorACK(::ZORG::Error& e, const char * LOGC, const Blob& rawErrorACKData, ErrorACK& cookedErrorACK)
{
    return cookEmptyMessage(e, LOGC, rawErrorACKData, cookedErrorACK, MessageTypeErrorACK);
}

struct RawGoClear: public RawMessageBody
{
    Words<2> mac;
};

struct RawClearACK: public RawMessageBody {};

const ClearACK& cookClearACK(::ZORG::Error& e, const char * LOGC, const Blob& rawClearACKData, ClearACK& cookedClearACK)
{
    return cookEmptyMessage(e, LOGC, rawClearACKData, cookedClearACK, MessageTypeClearACK);
}

struct RawRelayACK: public RawMessageBody {};

const RelayACK& cookRelayACK(::ZORG::Error& e, const char * LOGC, const Blob& rawRelayACKData, RelayACK& cookedRelayACK)
{
    return cookEmptyMessage(e, LOGC, rawRelayACKData, cookedRelayACK, MessageTypeRelayACK);
}

struct RawPing: public RawMessageBody
{
    Word version;
    Words<2> endpointHash;
};

const Ping& cookPing(::ZORG::Error& e, const char * LOGC, const Blob& rawPingData, Ping& cookedPing)
{
    if(ZORG_FAILURE(e))
	return cookedPing;

    if(rawPingData.dataSize != sizeof(RawPing))
    {
	ZORG_LOG(3,(LOGC, "message has bad body length (expected: %u; actual: %u): terminating", sizeof(RawPing), rawPingData.dataSize));
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return cookedPing;
    }

    const RawPing& rawPing = *static_cast<RawPing *>(rawPingData.buffer);

    // message is good, cook it
    cookedPing.type = MessageTypePing;
    cookedPing.version = cookProtocolVersion(e, rawPing.version);
    cookedPing.endpointHash = rawPing.endpointHash;

    return cookedPing;
}

struct RawPingACK: public RawMessageBody
{
    Word version;
    Words<2> senderEndpointHash;
    Words<2> receivedEndpointHash;
    SSRC receivedSSRC;
};

const PingACK& cookPingACK(::ZORG::Error& e, const char * LOGC, const Blob& rawPingACKData, PingACK& cookedPingACK)
{
    if(ZORG_FAILURE(e))
	return cookedPingACK;

    if(rawPingACKData.dataSize != sizeof(RawPingACK))
    {
	ZORG_LOG(3,(LOGC, "message has bad body length (expected: %u; actual: %u): terminating", sizeof(RawPingACK), rawPingACKData.dataSize));
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return cookedPingACK;
    }

    const RawPingACK& rawPingACK = *static_cast<RawPingACK *>(rawPingACKData.buffer);

    // message is good, cook it
    cookedPingACK.type = MessageTypePingACK;
    cookedPingACK.version = cookProtocolVersion(e, rawPingACK.version);
    cookedPingACK.senderEndpointHash = rawPingACK.senderEndpointHash;
    cookedPingACK.receivedEndpointHash = rawPingACK.receivedEndpointHash;
    cookedPingACK.receivedSSRC = rawPingACK.receivedSSRC;

    return cookedPingACK;
}

bool isKeyAgreementDH(KeyAgreementType keyAgreementType)
{
    switch(keyAgreementType)
    {
    case KeyAgreementDH3k:
    case KeyAgreementDH2k:
    case KeyAgreementEC25:
    case KeyAgreementEC38:
    case KeyAgreementEC52:
	return true;

    case KeyAgreementPrsh:
    case KeyAgreementMult:
	return false;

    default:
	ZORG_UNREACHABLE();
	return false;
    }
}

KeyAgreementType fasterDHKeyAgreementType(::ZORG::Error& e, KeyAgreementType x, KeyAgreementType y)
{
    if(ZORG_FAILURE(e))
	return KeyAgreementUnknown;

    static const int KeyAgreementRank[] =
    {
	-1, // KeyAgreementUnknown
	2,  // KeyAgreementDH3k
	0,  // KeyAgreementDH2k
	1,  // KeyAgreementEC25
	3,  // KeyAgreementEC38
	4,  // KeyAgreementEC52
	-1, // KeyAgreementPrsh
	-1, // KeyAgreementMult
    };

    assert(x > KeyAgreementUnknown && x < KeyAgreementTop && isKeyAgreementDH(x));

    if(!(x > KeyAgreementUnknown && x < KeyAgreementTop && isKeyAgreementDH(x)))
    {
	ZORG_SET_ERROR(e, ErrorInternal);
	return KeyAgreementUnknown;
    }

    assert(y > KeyAgreementUnknown && y < KeyAgreementTop && isKeyAgreementDH(y));

    if(!(y > KeyAgreementUnknown && y < KeyAgreementTop && isKeyAgreementDH(y)))
    {
	ZORG_SET_ERROR(e, ErrorInternal);
	return KeyAgreementUnknown;
    }

    int rankX = KeyAgreementRank[x];
    int rankY = KeyAgreementRank[y];

    if(rankX < rankY)
	return x;
    else
	return y;
}

Words<8> calculateHvi(::ZORG::Error& e, Crypto::HashFunction * hashFunction, const Blob& dhPart2, const Blob& responderHello)
{
    Words<8> hviValue;
    std::auto_ptr<Crypto::Hash> hvi(hashFunction->Create(e));

    if(ZORG_SUCCESS(e))
    {
	hvi->next(e, dhPart2);
	hvi->next(e, responderHello);
	truncatedCopy(e, hvi->finish(e, asBlob(BitArray<MAX_HASH_BITS>())), asBlob(hviValue));
	hvi.release();
    }

    return hviValue;
}

}

namespace Internal
{

struct LargestRawHello: public RawHello
{
    Word largestHashAlgorithms[7];
    Word largestCipherAlgorithms[7];
    Word largestAuthTagTypes[7];
    Word largestKeyAgreementTypes[7];
    Word largestSASTypes[7];
    Words<2> mac;
};

typedef RawHelloACK LargestRawHelloACK;

union LargestRawCommit
{
    RawCommitDH dh;
    RawCommitMult mult;
    RawCommitPrsh prsh;
};

struct LargestRawDHPart1: public RawDHPart1
{
    BitArray<MAX_PV_BITS> largestPvr;
    Words<2> mac;
};

struct LargestRawDHPart2: public RawDHPart2
{
    BitArray<MAX_PV_BITS> largestPvi;
    Words<2> mac;
};

struct LargestRawConfirm: public RawConfirm
{
    Word signatureType;
    Words<0x1ff> largestSignature;
};

typedef LargestRawConfirm LargestRawConfirm1, LargestRawConfirm2;

typedef RawConf2ACK LargestRawConf2ACK;
typedef RawError LargestRawError;
typedef RawErrorACK LargestRawErrorACK;
typedef RawGoClear LargestRawGoClear;
typedef RawClearACK LargestRawClearACK;
//typedef RawSASrelay LargestRawSASrelay; // TBD
typedef RawRelayACK LargestRawRelayACK;
typedef RawPing LargestRawPing;
typedef RawPingACK LargestRawPingACK;

union LargestMessage
{
    LargestRawHello hello;
    LargestRawHelloACK helloACK;
    LargestRawCommit commit;
    LargestRawDHPart1 dhPart1;
    LargestRawDHPart2 dhPart2;
    LargestRawConfirm1 confirm1;
    LargestRawConfirm2 confirm2;
    LargestRawConf2ACK conf2ACK;
    LargestRawError error;
    LargestRawErrorACK errorACK;
    LargestRawGoClear goClear;
    LargestRawClearACK clearACK;
    //LargestRawSASrelay sasRelay; // TBD
    LargestRawRelayACK relayACK;
    LargestRawPing ping;
    LargestRawPingACK pingACK;
};

const size_t MAX_RAW_MESSAGE_SIZES[] =
{
    0,                                      // MessageTypeNone
    sizeof(LargestRawHello),                // MessageTypeHello
    sizeof(LargestRawHelloACK),             // MessageTypeHelloACK
    sizeof(LargestRawCommit),               // MessageTypeCommit
    sizeof(LargestRawDHPart1),              // MessageTypeDHPart1
    sizeof(LargestRawDHPart2),              // MessageTypeDHPart2
    sizeof(LargestRawConfirm1),             // MessageTypeConfirm1
    sizeof(LargestRawConfirm2),             // MessageTypeConfirm2
    sizeof(LargestRawConf2ACK),             // MessageTypeConf2ACK
    sizeof(LargestRawError),                // MessageTypeError
    sizeof(LargestRawErrorACK),             // MessageTypeErrorACK
    sizeof(LargestRawGoClear),              // MessageTypeGoClear
    sizeof(LargestRawClearACK),             // MessageTypeClearACK
    0 /*TBD: sizeof(LargestRawSASrelay)*/, // MessageTypeSASrelay
    sizeof(LargestRawRelayACK),             // MessageTypeRelayACK
    sizeof(LargestRawPing),                 // MessageTypePing
    sizeof(LargestRawPingACK)               // MessageTypePingACK
};

struct FormatMessageType: public std::unary_function<MessageType, MessageTypeBlock>
{
    MessageTypeBlock operator()(MessageType cooked) const
    {
	switch(cooked)
	{
	case MessageTypeHello: return asMessageTypeBlock("Hello   ");
	case MessageTypeHelloACK: return asMessageTypeBlock("HelloACK");
	case MessageTypeCommit: return asMessageTypeBlock("Commit  ");
	case MessageTypeDHPart1: return asMessageTypeBlock("DHPart1 ");
	case MessageTypeDHPart2: return asMessageTypeBlock("DHPart2 ");
	case MessageTypeConfirm1: return asMessageTypeBlock("Confirm1");
	case MessageTypeConfirm2: return asMessageTypeBlock("Confirm2");
	case MessageTypeConf2ACK: return asMessageTypeBlock("Conf2ACK");
	case MessageTypeError: return asMessageTypeBlock("Error   ");
	case MessageTypeErrorACK: return asMessageTypeBlock("ErrorACK");
	case MessageTypeGoClear: return asMessageTypeBlock("GoClear ");
	case MessageTypeClearACK: return asMessageTypeBlock("ClearACK");
	case MessageTypeSASrelay: return asMessageTypeBlock("SASrelay");
	case MessageTypeRelayACK: return asMessageTypeBlock("RelayACK");
	case MessageTypePing: return asMessageTypeBlock("Ping    ");
	case MessageTypePingACK: return asMessageTypeBlock("PingACK ");

	case MessageTypeNone:
	case MessageTypeUnknown:
	    break;
	}

	ZORG_UNREACHABLE();
	return asMessageTypeBlock("\0x00\0x00\0x00\0x00\0x00\0x00\0x00\0x00");
    };
};

const FormatMessageType formatMessageType = FormatMessageType();

struct FormatProtocolVersion: public std::unary_function<ProtocolVersion, Word>
{
    Word operator()(ProtocolVersion cooked) const
    {
	switch(cooked)
	{
	case ProtocolVersion1_10: return AsWord("1.10");

	case ProtocolVersionUnknown:
	case ProtocolVersionUnsupported:
	    break;
	}

	ZORG_UNREACHABLE();
	return AsWord("\0x00\0x00\0x00\0x00");
    };
};

const FormatProtocolVersion formatProtocolVersion = FormatProtocolVersion();

struct FormatHashAlgorithm: public std::unary_function<HashAlgorithm, Word>
{
    Word operator()(HashAlgorithm cooked) const
    {
	switch(cooked)
	{
	case HashS256: return AsWord("S256");
	case HashS384: return AsWord("S384");
	case HashN256: return AsWord("N256");
	case HashN384: return AsWord("N384");

	default:
	    break;
	}

	ZORG_UNREACHABLE();
	return AsWord("\0x00\0x00\0x00\0x00");
    };
};

const FormatHashAlgorithm formatHashAlgorithm = FormatHashAlgorithm();

struct FormatCipherAlgorithm: public std::unary_function<CipherAlgorithm, Word>
{
    Word operator()(CipherAlgorithm cooked) const
    {
	switch(cooked)
	{
	case CipherAES1: return AsWord("AES1");
	case CipherAES2: return AsWord("AES2");
	case CipherAES3: return AsWord("AES3");
	case Cipher2FS1: return AsWord("2FS1");
	case Cipher2FS2: return AsWord("2FS2");
	case Cipher2FS3: return AsWord("2FS3");
	case CipherCAM1: return AsWord("CAM1");
	case CipherCAM2: return AsWord("CAM2");
	case CipherCAM3: return AsWord("CAM3");
	
	default:
	    break;
	}

	ZORG_UNREACHABLE();
	return AsWord("\0x00\0x00\0x00\0x00");
    };
};

const FormatCipherAlgorithm formatCipherAlgorithm = FormatCipherAlgorithm();

struct FormatAuthTagType: public std::unary_function<AuthTagType, Word>
{
    Word operator()(AuthTagType cooked) const
    {
	switch(cooked)
	{
	case AuthTagHS32: return AsWord("HS32");
	case AuthTagHS80: return AsWord("HS80");
	case AuthTagSK32: return AsWord("SK32");
	case AuthTagSK64: return AsWord("SK64");
	
	default:
	    break;
	}

	ZORG_UNREACHABLE();
	return AsWord("\0x00\0x00\0x00\0x00");
    };
};

const FormatAuthTagType formatAuthTagType = FormatAuthTagType();

struct FormatKeyAgreementType: public std::unary_function<KeyAgreementType, Word>
{
    Word operator()(KeyAgreementType cooked) const
    {
	switch(cooked)
	{
	case KeyAgreementDH3k: return AsWord("DH3k");
	case KeyAgreementDH2k: return AsWord("DH2k");
	case KeyAgreementEC25: return AsWord("EC25");
	case KeyAgreementEC38: return AsWord("EC38");
	case KeyAgreementEC52: return AsWord("EC52");
	case KeyAgreementPrsh: return AsWord("Prsh");
	case KeyAgreementMult: return AsWord("Mult");
	
	default:
	    break;
	}

	ZORG_UNREACHABLE();
	return AsWord("\0x00\0x00\0x00\0x00");
    };
};

const FormatKeyAgreementType formatKeyAgreementType = FormatKeyAgreementType();

struct FormatSASType: public std::unary_function<SASType, Word>
{
    Word operator()(SASType cooked) const
    {
	switch(cooked)
	{
	case SASB32: return AsWord("B32 ");
	case SASB256: return AsWord("B256");

	default:
	    break;
	}

	ZORG_UNREACHABLE();
	return AsWord("\0x00\0x00\0x00\0x00");
    };
};

const FormatSASType formatSASType = FormatSASType();

void formatMessagePacket(::ZORG::Error& e, uint16_t sequenceNumber, const SSRC& ssrc, Blob& data, CRC& crc)
{
    if(ZORG_FAILURE(e))
	return;

    if(data.dataSize % WORD_BYTES)
    {
	ZORG_SET_ERROR(e, ErrorDataSize);
	return;
    }

    if(data.dataSize < sizeof(RawMessageHeader))
    {
	ZORG_SET_ERROR(e, ErrorDataSize);
	return;
    }

    RawMessageHeader& rawHeader = *static_cast<RawMessageHeader *>(data.buffer);
    rawHeader.header = asBitArray<16>("\x10\x00");
    rawHeader.sequenceNumber = int16_BE(sequenceNumber);
    rawHeader.magicCookie = asBitArray<32>("ZRTP");
    rawHeader.ssrc = ssrc;

    copy(crc, Impl::CRC32C(data));
}

void formatMessagePacket(::ZORG::Error& e, uint16_t sequenceNumber, const SSRC& ssrc, const Blob& data, CRC& crc)
{
    Blob tmp = data;
    formatMessagePacket(e, sequenceNumber, ssrc, tmp, crc);
}

const RawMessageBody& formatMessageBody(::ZORG::Error& e, MessageType messageType, size_t messageSize, RawMessageBody& rawBody)
{
    if(ZORG_FAILURE(e))
	return rawBody;

    if(messageSize % WORD_BYTES)
    {
	ZORG_SET_ERROR(e, ErrorDataSize);
	return rawBody;
    }

    if(messageSize / WORD_BYTES > 0xFFFF)
    {
	ZORG_SET_ERROR(e, ErrorDataSize);
	return rawBody;
    }

    rawBody.preamble = asBitArray<16>("\x50\x5a");
    rawBody.length = int16_BE(messageSize / WORD_BYTES);
    rawBody.messageTypeBlock = formatMessageType(messageType);

    return rawBody;
}

const Blob& formatEmptyMessage(::ZORG::Error& e, MessageType messageType, Blob& rawMessageData)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    if(rawMessageData.maxSize < sizeof(RawMessageBody))
    {
	ZORG_SET_ERROR(e, ErrorBufferSize); 
	return NullBlob;
    }
    
    formatMessageBody(e, messageType, sizeof(RawMessageBody), *static_cast<RawMessageBody *>(rawMessageData.buffer));
    rawMessageData.dataSize = sizeof(RawMessageBody);

    return rawMessageData;
}

Blob formatEmptyMessage(::ZORG::Error& e, MessageType messageType, const Blob& rawMessageData)
{
    Blob tmp = rawMessageData;
    return formatEmptyMessage(e, messageType, tmp);
}

const Blob& formatHello(::ZORG::Error& e, const Hello& cookedHello, Crypto::HashFunction * implicitHashFunction, const Blob& h2, Blob& rawHelloData)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    size_t hashAlgorithmsCount = cookedHello.hashAlgorithms.size();
    size_t cipherAlgorithmsCount = cookedHello.cipherAlgorithms.size();
    size_t authTagTypesCount = cookedHello.authTagTypes.size();
    size_t keyAgreementTypesCount = cookedHello.keyAgreementTypes.size();
    size_t sasTypesCount = cookedHello.sasTypes.size();

    if(hashAlgorithmsCount > 7 || cipherAlgorithmsCount > 7 || authTagTypesCount > 7 || keyAgreementTypesCount > 7 || sasTypesCount > 7)
    {
	ZORG_SET_ERROR(e, ErrorZRTPBadProfile);
	return NullBlob;
    }

    size_t requiredSize =
	sizeof(RawHello) +
	hashAlgorithmsCount * sizeof(Word) +
	cipherAlgorithmsCount * sizeof(Word) +
	authTagTypesCount * sizeof(Word) +
	keyAgreementTypesCount * sizeof(Word) +
	sasTypesCount * sizeof(Word);

    size_t requiredSizeTotal = requiredSize + sizeof(Words<2>);

    if(rawHelloData.maxSize < requiredSizeTotal)
    {
	ZORG_SET_ERROR(e, ErrorBufferSize);
	return NullBlob;
    }

    RawHello& rawHello = *static_cast<RawHello *>(rawHelloData.buffer);
    Word * rawHashAlgorithms = reinterpret_cast<Word *>(&rawHello + 1);
    Word * rawCipherAlgorithms = rawHashAlgorithms + hashAlgorithmsCount;
    Word * rawAuthTagTypes = rawCipherAlgorithms + cipherAlgorithmsCount;
    Word * rawKeyAgreementTypes = rawAuthTagTypes + authTagTypesCount;
    Word * rawSASTypes = rawKeyAgreementTypes + keyAgreementTypesCount;
    Words<2>& rawMAC = *reinterpret_cast<Words<2> *>(rawSASTypes + sasTypesCount);

    formatMessageBody(e, MessageTypeHello, requiredSizeTotal, rawHello);

    rawHello.version = formatProtocolVersion(cookedHello.version);
    memcpy(rawHello.clientId.bytes, cookedHello.clientId, sizeof(rawHello.clientId));
    rawHello.h3 = cookedHello.h3;
    rawHello.zid = cookedHello.zid;
    
    rawHello.flagsAndProfileSize.bytes[0] =
	0x40 * !!cookedHello.streamFlags.signatureCapable +
	0x20 * !!cookedHello.streamFlags.mitm +
	0x10 * !!cookedHello.streamFlags.passive;

    rawHello.flagsAndProfileSize.bytes[1] = hashAlgorithmsCount;
    rawHello.flagsAndProfileSize.bytes[2] = (cipherAlgorithmsCount << 4) + authTagTypesCount;
    rawHello.flagsAndProfileSize.bytes[3] = (keyAgreementTypesCount << 4) + sasTypesCount;

    std::transform(cookedHello.hashAlgorithms.begin(), cookedHello.hashAlgorithms.end(), rawHashAlgorithms, formatHashAlgorithm);
    std::transform(cookedHello.cipherAlgorithms.begin(), cookedHello.cipherAlgorithms.end(), rawCipherAlgorithms, formatCipherAlgorithm);
    std::transform(cookedHello.authTagTypes.begin(), cookedHello.authTagTypes.end(), rawAuthTagTypes, formatAuthTagType);
    std::transform(cookedHello.keyAgreementTypes.begin(), cookedHello.keyAgreementTypes.end(), rawKeyAgreementTypes, formatKeyAgreementType);
    std::transform(cookedHello.sasTypes.begin(), cookedHello.sasTypes.end(), rawSASTypes, formatSASType);

    rawHelloData.dataSize = requiredSize;
    truncatedCopy(e, implicitHashFunction->mac(e, h2, rawHelloData, asBlob(BitArray<IMPLICIT_MAC_BITS>())), asBlob(rawMAC));

    rawHelloData.dataSize = requiredSizeTotal;
    return rawHelloData;
}

Blob formatHello(::ZORG::Error& e, const Hello& cookedHello, Crypto::HashFunction * implicitHashFunction, const Blob& h2, const Blob& rawHelloData)
{
    Blob tmp = rawHelloData;
    return formatHello(e, cookedHello, implicitHashFunction, h2, tmp);
}

const Blob& formatHelloACK(::ZORG::Error& e, Blob& rawHelloACKData)
{
    return formatEmptyMessage(e, MessageTypeHelloACK, rawHelloACKData);
}

Blob formatHelloACK(::ZORG::Error& e, const Blob& rawHelloACKData)
{
    Blob tmp = rawHelloACKData;
    return formatHelloACK(e, tmp);
}

const Blob& formatCommit(::ZORG::Error& e, const Commit& cookedCommit, Crypto::HashFunction * implicitHashFunction, const Blob& h1, Blob& rawCommitData)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    size_t rawSize;

    switch(cookedCommit.keyAgreementType)
    {
    case KeyAgreementUnknown:
	ZORG_UNREACHABLE_E(e);
	return NullBlob;

    case KeyAgreementMult:
	rawSize = sizeof(RawCommitMult);
	break;

    case KeyAgreementPrsh:
	rawSize = sizeof(RawCommitPrsh);
	break;

    default:
	rawSize = sizeof(RawCommitDH);
	break;
    }

    if(rawSize > rawCommitData.maxSize)
    {
	ZORG_SET_ERROR(e, ErrorBufferSize);
	return NullBlob;
    }

    RawCommit& rawCommit = *static_cast<RawCommit *>(rawCommitData.buffer);

    rawCommit.h2 = cookedCommit.h2;
    rawCommit.zid = cookedCommit.zid;
    rawCommit.hashAlgorithm = formatHashAlgorithm(cookedCommit.hashAlgorithm);
    rawCommit.cipherAlgorithm = formatCipherAlgorithm(cookedCommit.cipherAlgorithm);
    rawCommit.authTagType = formatAuthTagType(cookedCommit.authTagType);
    rawCommit.keyAgreementType = formatKeyAgreementType(cookedCommit.keyAgreementType);
    rawCommit.sasType = formatSASType(cookedCommit.sasType);

    Blob mac;

    Blob macData;
    macData.buffer = &rawCommit;

    switch(cookedCommit.keyAgreementType)
    {
    case KeyAgreementUnknown:
	ZORG_UNREACHABLE_E(e);
	return NullBlob;

    case KeyAgreementMult:
	{
	    RawCommitMult& rawCommitMult = static_cast<RawCommitMult&>(rawCommit);
	    formatMessageBody(e, MessageTypeCommit, sizeof(RawCommitMult), rawCommitMult);
	    rawCommitMult.nonce = cookedCommit.kaparam.mult.nonce;
	    mac = asBlob(rawCommitMult.mac);
	    macData.dataSize = offsetof(RawCommitMult, mac);
	    rawCommitData.dataSize = sizeof(RawCommitMult);
	}

	break;

    case KeyAgreementPrsh:
	{
	    RawCommitPrsh& rawCommitPrsh = static_cast<RawCommitPrsh&>(rawCommit);
	    formatMessageBody(e, MessageTypeCommit, sizeof(RawCommitPrsh), rawCommitPrsh);
	    rawCommitPrsh.nonce = cookedCommit.kaparam.prsh.nonce;
	    rawCommitPrsh.keyID = cookedCommit.kaparam.prsh.keyID;
	    mac = asBlob(rawCommitPrsh.mac);
	    macData.dataSize = offsetof(RawCommitPrsh, mac);
	    rawCommitData.dataSize = sizeof(RawCommitPrsh);
	}

	break;

    default:
	{
	    RawCommitDH& rawCommitDH = static_cast<RawCommitDH&>(rawCommit);
	    formatMessageBody(e, MessageTypeCommit, sizeof(RawCommitDH), rawCommitDH);
	    rawCommitDH.hvi = cookedCommit.kaparam.dh.hvi;
	    mac = asBlob(rawCommitDH.mac);
	    macData.dataSize = offsetof(RawCommitDH, mac);
	    rawCommitData.dataSize = sizeof(RawCommitDH);
	}

	break;
    }

    truncatedCopy(e, implicitHashFunction->mac(e, h1, macData, asBlob(BitArray<MAX_HASH_BITS>())), mac);

    return rawCommitData;
}

Blob formatCommit(::ZORG::Error& e, const Commit& cookedCommit, Crypto::HashFunction * implicitHashFunction, const Blob& h1, const Blob& rawCommitData)
{
    Blob tmp = rawCommitData;
    return formatCommit(e, cookedCommit, implicitHashFunction, h1, tmp);
}

const Blob& formatDHPart1(::ZORG::Error& e, const DHPart1& cookedDHPart1, Crypto::HashFunction * implicitHashFunction, KeyAgreementType keyAgreementType, const Blob& h0, Blob& rawDHPart1Data)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    size_t pvrSize = getPVSize(e, keyAgreementType);
    size_t requiredSize = sizeof(RawDHPart1) + pvrSize;
    size_t requiredSizeTotal = requiredSize + sizeof(Words<2>);

    if(rawDHPart1Data.maxSize < requiredSizeTotal)
    {
	ZORG_SET_ERROR(e, ErrorBufferSize);
	return NullBlob;
    }

    if(cookedDHPart1.pvr.dataSize != pvrSize)
    {
	ZORG_SET_ERROR(e, ErrorDataSize);
	return NullBlob;
    }

    RawDHPart1& rawDHPart1 = *static_cast<RawDHPart1 *>(rawDHPart1Data.buffer);
    char * rawPvr = reinterpret_cast<char *>(&rawDHPart1 + 1);
    Words<2>& rawMAC = *reinterpret_cast<Words<2> *>(rawPvr + pvrSize);

    formatMessageBody(e, MessageTypeDHPart1, requiredSizeTotal, rawDHPart1);
    rawDHPart1.h1 = cookedDHPart1.h1;
    rawDHPart1.rs1IDr = cookedDHPart1.rs1IDr;
    rawDHPart1.rs2IDr = cookedDHPart1.rs2IDr;
    rawDHPart1.auxsecretIDr = cookedDHPart1.auxsecretIDr;
    rawDHPart1.pbxsecretIDr = cookedDHPart1.pbxsecretIDr;
    memcpy(rawPvr, cookedDHPart1.pvr.buffer, cookedDHPart1.pvr.dataSize);

    rawDHPart1Data.dataSize = requiredSize;
    truncatedCopy(e, implicitHashFunction->mac(e, h0, rawDHPart1Data, asBlob(BitArray<IMPLICIT_MAC_BITS>())), asBlob(rawMAC));

    rawDHPart1Data.dataSize = requiredSizeTotal;

    return rawDHPart1Data;
}

Blob formatDHPart1(::ZORG::Error& e, const DHPart1& cookedDHPart1, Crypto::HashFunction * implicitHashFunction, KeyAgreementType keyAgreementType, const Blob& h0, const Blob& rawDHPart1Data)
{
    Blob tmp = rawDHPart1Data;
    return formatDHPart1(e, cookedDHPart1, implicitHashFunction, keyAgreementType, h0, tmp);
}

const Blob& formatDHPart2(::ZORG::Error& e, const DHPart2& cookedDHPart2, Crypto::HashFunction * implicitHashFunction, KeyAgreementType keyAgreementType, const Blob& h0, Blob& rawDHPart2Data)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    size_t pviSize = getPVSize(e, keyAgreementType);
    size_t requiredSize = sizeof(RawDHPart2) + pviSize;
    size_t requiredSizeTotal = requiredSize + sizeof(Words<2>);

    if(rawDHPart2Data.maxSize < requiredSizeTotal)
    {
	ZORG_SET_ERROR(e, ErrorBufferSize);
	return NullBlob;
    }

    if(cookedDHPart2.pvi.dataSize != pviSize)
    {
	ZORG_SET_ERROR(e, ErrorDataSize);
	return NullBlob;
    }

    RawDHPart2& rawDHPart2 = *static_cast<RawDHPart2 *>(rawDHPart2Data.buffer);
    char * rawPvi = reinterpret_cast<char *>(&rawDHPart2 + 1);
    Words<2>& rawMAC = *reinterpret_cast<Words<2> *>(rawPvi + pviSize);

    formatMessageBody(e, MessageTypeDHPart2, requiredSizeTotal, rawDHPart2);
    rawDHPart2.h1 = cookedDHPart2.h1;
    rawDHPart2.rs1IDi = cookedDHPart2.rs1IDi;
    rawDHPart2.rs2IDi = cookedDHPart2.rs2IDi;
    rawDHPart2.auxsecretIDi = cookedDHPart2.auxsecretIDi;
    rawDHPart2.pbxsecretIDi = cookedDHPart2.pbxsecretIDi;
    memcpy(rawPvi, cookedDHPart2.pvi.buffer, cookedDHPart2.pvi.dataSize);

    rawDHPart2Data.dataSize = requiredSize;
    truncatedCopy(e, implicitHashFunction->mac(e, h0, rawDHPart2Data, asBlob(BitArray<IMPLICIT_MAC_BITS>())), asBlob(rawMAC));

    rawDHPart2Data.dataSize = requiredSizeTotal;
    return rawDHPart2Data;
}

Blob formatDHPart2(::ZORG::Error& e, const DHPart2& cookedDHPart2, Crypto::HashFunction * implicitHashFunction, KeyAgreementType keyAgreementType, const Blob& h0, const Blob& rawDHPart2Data)
{
    Blob tmp = rawDHPart2Data;
    return formatDHPart2(e, cookedDHPart2, implicitHashFunction, keyAgreementType, h0, tmp);
}

const Blob& encryptCFB(::ZORG::Error& e, Crypto::CipherFunction * cipherFunction, const Blob& key, const Blob& iv, const Blob& decrypted, Blob& encrypted)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    if(encrypted.maxSize < decrypted.dataSize)
    {
	ZORG_SET_ERROR(e, ErrorBufferSize);
	return NullBlob;
    }

    Blob actualKey = key;
    assert(actualKey.dataSize >= cipherFunction->getKeyBytes());
    actualKey.dataSize = cipherFunction->getKeyBytes();

    Blob actualIV = iv;
    assert(actualIV.dataSize >= cipherFunction->getCFBIVBytes());
    actualIV.dataSize = cipherFunction->getCFBIVBytes();

    std::auto_ptr<Crypto::Cipher> encryptor(cipherFunction->CreateEncryptorCFB(e, actualKey, actualIV));

    if(ZORG_FAILURE(e))
	return NullBlob;

    size_t cipherBlockBits = cipherFunction->getBlockBits();
    assert(cipherBlockBits % CHAR_BIT == 0);
    assert(cipherBlockBits <= MAX_CIPHER_BLOCK_BITS);

    size_t cipherBlockBytes = cipherBlockBits / CHAR_BIT;

    unsigned char * in = static_cast<unsigned char *>(decrypted.buffer);
    unsigned char * out = static_cast<unsigned char *>(encrypted.buffer);

    size_t inSize = decrypted.dataSize;

    Blob inBlock;
    inBlock.dataSize = cipherBlockBytes;
    inBlock.maxSize = cipherBlockBytes;

    Blob outBlock;
    outBlock.dataSize = cipherBlockBytes;
    outBlock.maxSize = cipherBlockBytes;

    for(; inSize >= cipherBlockBytes; inSize -= cipherBlockBytes, in += cipherBlockBytes, out += cipherBlockBytes)
    {
	inBlock.buffer = in;
	outBlock.buffer = out;

	encryptor->processBlock(e, inBlock, outBlock);

	assert(outBlock.dataSize == outBlock.maxSize);
	assert(outBlock.dataSize == cipherBlockBytes);
    }

    if(inSize)
    {
	inBlock.dataSize = inSize;
	inBlock.buffer = in;

	outBlock.buffer = out;

	encryptor->processBlock(e, inBlock, outBlock);

	assert(outBlock.dataSize == inSize);
    }

    encrypted.dataSize = decrypted.dataSize;
    return encrypted;
}

Blob encryptCFB(::ZORG::Error& e, Crypto::CipherFunction * cipherFunction, const Blob& key, const Blob& iv, const Blob& decrypted, const Blob& encrypted)
{
    Blob tmp = encrypted;
    return encryptCFB(e, cipherFunction, key, iv, decrypted, tmp);
}

const Blob& formatConfirm(::ZORG::Error& e, const Confirm& cookedConfirm, MessageType messageType, Crypto::HashFunction * hashFunction, const Blob& mackey, Crypto::CipherFunction * cipherFunction, const Blob& zrtpkey, Blob& rawConfirmData)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    if(rawConfirmData.maxSize < sizeof(RawConfirm)) // TBD: this check assumes no signature
    {
	ZORG_SET_ERROR(e, ErrorBufferSize);
	return NullBlob;
    }

    RawConfirm& rawConfirm = *static_cast<RawConfirm *>(rawConfirmData.buffer);
    formatMessageBody(e, messageType, sizeof(RawConfirm), rawConfirm);
    rawConfirm.cfbIV = cookedConfirm.cfbIV;
    
    RawConfirmEncryptedPart rawConfirmBody;
    rawConfirmBody.h0 = cookedConfirm.h0;
    rawConfirmBody.sigLenAndFlags.bytes[0] = 0;
    rawConfirmBody.sigLenAndFlags.bytes[1] = 0; // TBD: signature length here
    rawConfirmBody.sigLenAndFlags.bytes[2] = 0; // TBD: signature length here
    rawConfirmBody.sigLenAndFlags.bytes[3] = 0x08 * !!(cookedConfirm.pbxEnrollment) | 0x04 * !!(cookedConfirm.sasVerified) | 0x02 * !!(cookedConfirm.allowClear) | 0x01 * !!(cookedConfirm.disclosure);
    copy(rawConfirmBody.cacheExpirationInterval, int32_BE(cookedConfirm.cacheExpirationInterval));

    encryptCFB(e, cipherFunction, zrtpkey, asBlob(rawConfirm.cfbIV), rawObjectAsBlob(rawConfirmBody), rawObjectAsBlob(rawConfirm.encrypted));

    truncatedCopy(e, hashFunction->mac(e, mackey, rawObjectAsBlob(rawConfirm.encrypted), asBlob(BitArray<MAX_MAC_BITS>())), asBlob(rawConfirm.confirmMAC));

    rawConfirmData.dataSize = sizeof(RawConfirm);
    return rawConfirmData;
}

Blob formatConfirm(::ZORG::Error& e, const Confirm& cookedConfirm, MessageType messageType, Crypto::HashFunction * hashFunction, const Blob& mackey, Crypto::CipherFunction * cipherFunction, const Blob& zrtpkey, const Blob& rawConfirmData)
{
    Blob tmp = rawConfirmData;
    return formatConfirm(e, cookedConfirm, messageType, hashFunction, mackey, cipherFunction, zrtpkey, tmp);
}

const Blob& formatConfirm1(::ZORG::Error& e, const Confirm1& cookedConfirm1, Crypto::HashFunction * hashFunction, const Blob& mackeyr, Crypto::CipherFunction * cipherFunction, const Blob& zrtpkeyr, Blob& rawConfirm1Data)
{
    return formatConfirm(e, cookedConfirm1, MessageTypeConfirm1, hashFunction, mackeyr, cipherFunction, zrtpkeyr, rawConfirm1Data);
}

Blob formatConfirm1(::ZORG::Error& e, const Confirm1& cookedConfirm1, Crypto::HashFunction * hashFunction, const Blob& mackeyr, Crypto::CipherFunction * cipherFunction, const Blob& zrtpkeyr, const Blob& rawConfirm1Data)
{
    Blob tmp = rawConfirm1Data;
    return formatConfirm1(e, cookedConfirm1, hashFunction, mackeyr, cipherFunction, zrtpkeyr, tmp);
}

const Blob& formatConfirm2(::ZORG::Error& e, const Confirm2& cookedConfirm2, Crypto::HashFunction * hashFunction, const Blob& mackeyi, Crypto::CipherFunction * cipherFunction, const Blob& zrtpkeyi, Blob& rawConfirm2Data)
{
    return formatConfirm(e, cookedConfirm2, MessageTypeConfirm2, hashFunction, mackeyi, cipherFunction, zrtpkeyi, rawConfirm2Data);
}

Blob formatConfirm2(::ZORG::Error& e, const Confirm1& cookedConfirm2, Crypto::HashFunction * hashFunction, const Blob& mackeyi, Crypto::CipherFunction * cipherFunction, const Blob& zrtpkeyi, const Blob& rawConfirm2Data)
{
    Blob tmp = rawConfirm2Data;
    return formatConfirm2(e, cookedConfirm2, hashFunction, mackeyi, cipherFunction, zrtpkeyi, tmp);
}

const Blob& formatConf2ACK(::ZORG::Error& e, Blob& rawConf2ACKData)
{
    return formatEmptyMessage(e, MessageTypeConf2ACK, rawConf2ACKData);
}

Blob formatConf2ACK(::ZORG::Error& e, const Blob& rawConf2ACKData)
{
    Blob tmp = rawConf2ACKData;
    return formatConf2ACK(e, tmp);
}

const Blob& formatError(::ZORG::Error& e, const Error& cookedError, Blob& rawErrorData)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    RawError& rawError = *static_cast<RawError *>(rawErrorData.buffer);
    formatMessageBody(e, MessageTypeError, sizeof(rawError), rawError);
    const BitArray<32>& errorCode = int32_BE(cookedError.errorCode);
    rawError.errorCode = reinterpret_cast<const Word&>(errorCode);

    rawErrorData.dataSize = sizeof(rawError);
    return rawErrorData;
}

Blob formatError(::ZORG::Error& e, const Error& cookedError, const Blob& rawErrorData)
{
    Blob tmp = rawErrorData;
    return formatError(e, cookedError, tmp);
}

const Blob& formatErrorACK(::ZORG::Error& e, Blob& rawErrorACKData)
{
    return formatEmptyMessage(e, MessageTypeErrorACK, rawErrorACKData);
}

Blob formatErrorACK(::ZORG::Error& e, const Blob& rawErrorACKData)
{
    Blob tmp = rawErrorACKData;
    return formatErrorACK(e, tmp);
}


}

namespace Internal
{

template<class Iter, class Value> Iter find_not(Iter begin, Iter end, const Value& val)
{
    return std::find_if(begin, end, std::not1(std::bind2nd(std::equal_to<Value>(), val)));
}

bool allZero(const Blob& data)
{
    return find_not(beginData(data), endData(data), 0) == endData(data);
}

void checkPV(::ZORG::Error& e, const Blob& pv, KeyAgreementType ka)
{
    if(ZORG_FAILURE(e))
	return;

    switch(ka)
    {
    case KeyAgreementDH3k:
    case KeyAgreementDH2k:
	// pv is 0 or 1
	if(allZero(leftData(pv, -1)) && (compareData(rightData(pv, 1), asBlob(byte(0))) == 0 || compareData(rightData(pv, 1), asBlob(byte(1))) == 0))
	    ZORG_SET_ERROR(e, asErrorCode(ErrorDHBadPV));
	// check if pv is p-1
	else
	{
	    Blob p;

	    switch(ka)
	    {
	    case KeyAgreementDH3k: p = Crypto::RFC3526::MODP3072.prime; break;
	    case KeyAgreementDH2k: p = Crypto::RFC3526::MODP2048.prime; break;
	    
	    default:
		ZORG_UNREACHABLE_E(e);
		return;
	    }

	    std::reverse_iterator<BlobIterator> curPV(endData(pv));
	    std::reverse_iterator<BlobIterator> endPV(find_not(beginData(pv), endData(pv), 0));
	    std::reverse_iterator<BlobIterator> curP(endData(p));
	    std::reverse_iterator<BlobIterator> endP(find_not(beginData(p), endData(p), 0));

	    uint8_t carry = 1;

	    for(; curPV != endPV && curP != endP; ++ curPV, ++ curP)
	    {
		uint16_t digit = static_cast<uint16_t>(*curPV) + carry;

		if((digit & 0xff) != *curP)
		    break;

		carry = !!(digit > 0xff);
	    }

	    if(curPV == endPV)
	    {
		if(!carry && curP == endP)
		    ZORG_SET_ERROR(e, asErrorCode(ErrorDHBadPV));
		else if(carry && std::distance(curP, endP) == 1 && *curP == 1)
		    ZORG_SET_ERROR(e, asErrorCode(ErrorDHBadPV));
	    }
	}

	break;

    case KeyAgreementEC25:
    case KeyAgreementEC38:
    case KeyAgreementEC52:
	break;

    default:
	ZORG_UNREACHABLE_E(e);
	break;
    }
}

const BitBlob<RS_BITS>& calculateS1(::ZORG::Error& e, const BitBlob<RS_BITS>& rs1, const BitBlob<RS_BITS>& rs2, const BitArray<RS_ID_BITS>& rs1ID, const BitArray<RS_ID_BITS>& rs2ID, const BitArray<RS_ID_BITS>& peerRS1ID, const BitArray<RS_ID_BITS>& peerRS2ID, BitBlob<RS_BITS>& s1, bool& continuityLost)
{
    if(ZORG_FAILURE(e))
	return s1;

    continuityLost = false;

    // The initiator's rs1 matches the responder's rs1
    if(rs1.dataSize && rs1ID == peerRS1ID)
    {
	// set s1 to the initiator's rs1
	s1 = rs1;
    }
    // Initiator: the initiator's rs1 matches the responder's rs2
    // Responder: the initiator's rs2 matches the responder's rs1
    else if(rs1.dataSize && rs1ID == peerRS2ID)
    {
	// Initiator: set s1 to the initiator's rs1 
	// Responder: set s1 to the initiator's rs2 
	s1 = rs1;
    }
    // Initiator: the initiator's rs2 matches the responder's rs1 
    // Responder: the initiator's rs1 matches the responder's rs2
    else if(rs2.dataSize && rs2ID == peerRS1ID)
    {
	// Initiator: set s1 to the initiator's rs2 
	// Responder: set s1 to the initiator's rs1
	s1 = rs2;
    }
    // The initiator's rs2 matches the responder's rs2
    else if(rs2.dataSize && rs2ID == peerRS2ID)
    {
	// the current session cannot be correlated with the cached one
	continuityLost = true;

	// set s1 to the initiator's rs2
	s1 = rs2;
    }
    // Cache mismatch or cache loss
    else
    {
	// the current session cannot be correlated with the cached one
	continuityLost = true;

	// s1 is NULL
	s1.dataSize = 0;
    }

    return s1;
}

class Instance;
class Session;
class Stream;

class Stream: public ::ZORG::ZRTP::Stream, public Task
{
private:
    friend class Session;

    char LOGC[LOGGING_CONTEXT_SIZE];
    List m_streamsEntry;
    Instance * const m_instance;
    Session * const m_session;
    StreamInterface * const m_iface;
    bool m_isInitiator;
    uint16_t m_sequenceNumber;
    SSRC m_ssrc;
    std::auto_ptr<SRTP::SRTPContext> m_srtpSend;
    std::auto_ptr<SRTP::SRTPContext> m_srtpRecv;
    StreamFlags m_flags; // TBD
    StreamFlags m_peerFlags;
    std::auto_ptr<Crypto::HashFunction> m_hashFunction;
    std::auto_ptr<Crypto::CipherFunction> m_cipherFunction;
    std::auto_ptr<Crypto::KeyExchangeFunction> m_keyExchangeFunction;
    ActiveProfile m_activeProfile;
    std::auto_ptr<Crypto::KeyExchange> m_keyExchange;
    BitBlob<IMPLICIT_HASH_BITS> m_expectedPeerHelloHash;
    BitBlob<IMPLICIT_HASH_BITS> m_peerHelloHash;
    RawMessageBuffer_T<LargestRawHello> m_hello;
    RawMessageBodyBuffer_T<LargestRawHello> m_peerHello;
    RawMessageBodyBuffer_T<LargestRawCommit> m_peerCommit;
    RawMessageBodyBuffer_T<LargestRawDHPart1> m_peerDHPart1;
    RawMessageBodyBuffer_T<LargestRawDHPart2> m_peerDHPart2;
    RawMessageBuffer_T<LargestRawCommit> m_commit;
    RawMessageBuffer_T<LargestRawDHPart1> m_dhPart1;
    RawMessageBuffer_T<LargestRawDHPart2> m_dhPart2;
    RawMessageBuffer_T<LargestRawConfirm2> m_confirm1;
    RawMessageBuffer_T<LargestRawConfirm2> m_confirm2;
    RawMessageFixedBuffer_T<LargestRawError> m_error;
    Words<8> m_peerH0;
    Words<8> m_peerH1;
    Words<8> m_peerH2;
    Words<8> m_peerH3;
    BitBlob<MAX_PV_BITS> m_pv;
    Words<8> m_hvi;
    Words<8> m_peerHvi;
    std::auto_ptr<Crypto::Hash> m_totalHash;
    BitBlob<MAX_HASH_BITS> m_totalHashValue;
    BitBlob<ZID::BITS + ZID::BITS + MAX_HASH_BITS> m_kdfContext;
    BitBlob<MAX_HASH_BITS> m_s0;
    bool m_verified;
    TaskCookie * m_retransmitTask;
    Blob m_retransmitPacket;
    MessageType m_retransmitPacketType;
    unsigned m_retransmitCounter;
    unsigned m_retransmitCap;
    int m_retransmitTimer;
    int m_retransmitTimerCap;

    enum State
    {
	StateUnknown = -1,
	StateStopped,
	StateNoZRTP,
	StateError,
	StateClear,
	StateSecure,
	StateLocalError,
	StateDiscovery,
	StateDiscoveryWaitHello,
	StateDiscoveryWaitHelloACK,
	StateResponderKeyAgreement,
	StateResponderConfirming,
	StateInitiatorKeyAgreement1,
	StateInitiatorKeyAgreement2,
	StateInitiatorConfirming
    }
    m_state;

    static const char * getStateName(State state)
    {
	switch(state)
	{
	case StateStopped: return "STOPPED";
	case StateNoZRTP: return "NO_ZRTP";
	case StateError: return "ERROR";
	case StateClear: return "CLEAR";
	case StateSecure: return "SECURE";
	case StateLocalError: return "LOCAL_ERROR";
	case StateDiscovery: return "DISCOVERY";
	case StateDiscoveryWaitHello: return "DISCOVERY_WAIT_HELLO";
	case StateDiscoveryWaitHelloACK: return "DISCOVERY_WAIT_HELLO_ACK";
	case StateResponderKeyAgreement: return "RESPONDER_KEY_AGREEMENT";
	case StateResponderConfirming: return "RESPONDER_CONFIRMING";
	case StateInitiatorKeyAgreement1: return "INITIATOR_KEY_AGREEMENT_1";
	case StateInitiatorKeyAgreement2: return "INITIATOR_KEY_AGREEMENT_2";
	case StateInitiatorConfirming: return "INITIATOR_CONFIRMING";
	default: ZORG_UNREACHABLE(); return "<unknown>";
	}
    }

    static bool isFinalState(State state)
    {
	switch(state)
	{
	case StateUnknown:
	    ZORG_UNREACHABLE();
	    break;

	case StateStopped:
	case StateNoZRTP:
	case StateError:
	    return true;

	default:
	    break;
	}

	return false;
    }

    static bool isDiscoveryState(State state)
    {
	switch(state)
	{
	case StateUnknown:
	    ZORG_UNREACHABLE();
	    break;

	case StateDiscovery:
	case StateDiscoveryWaitHello:
	case StateDiscoveryWaitHelloACK:
	    return true;

	default:
	    break;
	}

	return false;
    }

    static bool isKeyAgreementState(State state)
    {
	switch(state)
	{
	case StateUnknown:
	    ZORG_UNREACHABLE();
	    break;

	case StateResponderKeyAgreement:
	case StateInitiatorKeyAgreement1:
	case StateInitiatorKeyAgreement2:
	    return true;

	default:
	    break;
	}

	return false;
    }

    static bool isConfirmingState(State state)
    {
	switch(state)
	{
	case StateUnknown:
	    ZORG_UNREACHABLE();
	    break;

	case StateResponderConfirming:
	case StateInitiatorConfirming:
	    return true;

	default:
	    break;
	}

	return false;
    }

    void setState(::ZORG::Error& e, const char * LOGC, State newState)
    {
	if(ZORG_FAILURE(e))
	    return;

	ZORG_LOG(3,(LOGC, "switching from state %s to state %s", getStateName(m_state), getStateName(newState)));

	State oldState = m_state;

	assert(newState != oldState);

	if(newState == oldState)
	{
	    ZORG_SET_ERROR(e, ErrorInternal);
	    return;
	}

	m_state = newState;

	if(newState == StateError)
	    notifySecurityEvent(e, LOGC, SecurityEventError);

	if(newState == StateLocalError)
	    notifyProtocolEvent(e, LOGC, EventLocalError);
	else if(newState == StateClear)
	    notifyProtocolEvent(e, LOGC, EventClear);
	else if(newState == StateSecure)
	    notifyProtocolEvent(e, LOGC, EventSecure);
	else if(isDiscoveryState(newState))
	{
	    if(!isDiscoveryState(oldState))
		notifyProtocolEvent(e, LOGC, EventDiscovery);
	}
	else if(isKeyAgreementState(newState))
	{
	    if(!isKeyAgreementState(oldState))
		notifyProtocolEvent(e, LOGC, EventKeyAgreement);
	}
	else if(isConfirmingState(newState))
	{
	    if(!isConfirmingState(oldState))
		notifyProtocolEvent(e, LOGC, EventConfirming);
	}
	else if(isFinalState(newState))
	{
	    if(!isFinalState(oldState))
		notifyProtocolEvent(e, LOGC, EventStop);
	}
	else
	    ZORG_UNREACHABLE();
    }

    ::ZORG::ErrorCode m_localError;
    ::ZORG::ErrorCode m_remoteError;

    Crypto::RFC5764::SRTPProfile getRTPProfile(::ZORG::Error& e) const;
    Crypto::RFC5764::SRTPProfile getRTCPProfile(::ZORG::Error& e) const;

    void sendACK(::ZORG::Error& e, const char * LOGC, MessageType messageType);
    void sendError(::ZORG::Error& e, const char * LOGC, ::ZORG::ErrorCode stopErrorCode);

    void calculatePeerHelloHash(::ZORG::Error& e, const Blob& peerHello);
    void checkPeerHelloHash(::ZORG::Error& e);
    void handleHello(::ZORG::Error& e, const char * LOGC, Blob& rawMessage, const CookedMessage& message);
    State discoveryDone(::ZORG::Error& e, const char * LOGC);
    State handleCommit(::ZORG::Error& e, const char * LOGC, Blob& rawMessage, const CookedMessage& message);
    State secureDone(::ZORG::Error& e, const char * LOGC);
    const Blob& processMessage(::ZORG::Error& e, Blob& rawMessage, const CookedMessage& message);
    void addDHResultToHash(::ZORG::Error& e, Crypto::Hash * hash, const Blob& dhResult);

    void sendMessage(::ZORG::Error& e, const char * LOGC, const Blob& messagePacket);
    void sendMessage(::ZORG::Error& e, const char * LOGC, const Blob& messagePacket, MessageType messageType);
    void sendMessage(::ZORG::Error& e, const char * LOGC, const Blob& messagePacket, MessageType messageType, unsigned counter, int timer, int cap);
    void cancelSendMessage(::ZORG::Error& e);

    void notifyProtocolEvent(::ZORG::Error& e, const char * LOGC, Event evt);
    void notifySecurityEvent(::ZORG::Error& e, const char * LOGC, SecurityEvent evt);

    void detach();
    void optionalCleanup();
    void mandatoryCleanup();

public:
    Stream(::ZORG::Error& e, Instance * instance, Session * session, StreamInterface * iface, bool isInitiator);
    virtual ~Stream();

    virtual ::ZORG::ZRTP::Session * session() const;
    virtual StreamFlags flags() const;

    virtual void start(::ZORG::Error& e, const SSRC& ssrc);
    virtual void stop();
    virtual void halt(::ZORG::Error& e, const ::ZORG::Error& stopError);
    using ::ZORG::ZRTP::Stream::halt;
    virtual const Blob& getSDPZrtpHash(::ZORG::Error& e, Blob& a);
    virtual void setPeerSDPZrtpHash(::ZORG::Error& e, const Blob& a);

    virtual const Blob& protectRTP_InPlace(::ZORG::Error& e, Blob& rtpPacket);
    virtual const Blob& protectRTCP_InPlace(::ZORG::Error& e, Blob& rtcpPacket);
    virtual const Blob& unprotectSRTP_InPlace(::ZORG::Error& e, Blob& srtpPacket);
    virtual const Blob& unprotectSRTCP_InPlace(::ZORG::Error& e, Blob& srtcpPacket);

    virtual void run();
    virtual void cancel();
};

class Session: public ::ZORG::ZRTP::Session
{
private:
    friend class Stream;
    friend class Instance;

    char LOGC[LOGGING_CONTEXT_SIZE];
    List m_sessionsEntry;
    List m_streams;
    Instance * const m_instance;
    SessionInterface * const m_iface;
    Cache * const m_cache;
    const ZID m_zid;
    const Profile m_profile;
    const bool m_isInitiator;

    Words<8> m_h0;
    Words<8> m_h1;
    Words<8> m_h2;
    Words<8> m_h3;

    bool m_peerZidAvailable;
    bool m_sasAvailable;
    bool m_cacheMismatch;
    ZID m_peerZid;
    SASType m_sasType;
    Crypto::SASValue m_sasValue;
    BitBlob<RS_BITS> m_rs1;
    BitBlob<RS_BITS> m_rs2;
    BitBlob<RS_BITS> m_s1;
    Words<2> m_rs1ID;
    Words<2> m_rs2ID;
    Words<2> m_peerRS1ID;
    Words<2> m_peerRS2ID;
    uint32_t m_cacheExpirationInterval;

    bool sasVerifiedInternal();
    void setSASVerifiedInternal(bool isVerified);
    void updateCache();
    void lookupCache();

public:
    Session(::ZORG::Error& e, Instance * instance, SessionInterface * iface, Cache * cache, const ZID& zid, const Profile& profile, bool isInitiator);
    virtual ~Session();

    virtual const ::ZORG::ZRTP::Instance * instance();
    virtual const ZID& zid();
    virtual const ZID& peerZID(::ZORG::Error& e);
    virtual const Crypto::SASValue& sasValue(::ZORG::Error& e);
    virtual const Crypto::SAS& sas(::ZORG::Error& e, Crypto::SAS& sas);
    virtual bool sasVerified(::ZORG::Error& e);
    virtual void setSASVerified(::ZORG::Error& e, bool isVerified);
    virtual ::ZORG::ZRTP::Stream * createStream(::ZORG::Error& e, StreamInterface * iface);
};

class Instance: public ::ZORG::ZRTP::Instance
{
private:
    friend class Stream;
    friend class Session;

    char LOGC[LOGGING_CONTEXT_SIZE];
    List m_sessions;
    CryptoSuite * const m_cryptoSuite;
    SRTP::SRTPInstance * const m_srtp;
    std::auto_ptr<Crypto::HashFunction> m_implictHashFunction;
    std::auto_ptr<Crypto::RNG> m_rng;
    unsigned m_t1;
    unsigned m_t1Cap;
    unsigned m_t1MaxRetransmit;
    unsigned m_t2;
    unsigned m_t2Cap;
    unsigned m_t2MaxRetransmit;

private:
    Instance(::ZORG::Error& e, CryptoSuite * cryptoSuite, SRTP::SRTPInstance * srtpImpl);

public:
    static ::ZORG::ZRTP::Instance * Create(::ZORG::Error& e, CryptoSuite * cryptoSuite, SRTP::SRTPInstance * srtpImpl);
    virtual ~Instance();
    virtual Session * createSession(::ZORG::Error& e, SessionInterface * iface, Cache * cache, const ZID& zid, const Profile& profile, bool isInitiator);
    virtual void addEntropy(::ZORG::Error& e, const Blob& seed);
    virtual const Blob& generateRandom(::ZORG::Error& e, size_t nbyte, Blob& randbuf);
    using ::ZORG::ZRTP::Instance::generateRandom;
};

Stream::Stream(::ZORG::Error& e, Instance * instance, Session * session, StreamInterface * iface, bool isInitiator):
    m_instance(instance),
    m_session(session),
    m_iface(iface),
    m_isInitiator(isInitiator),
    m_flags(), // TBD
    m_verified(false),
    m_retransmitTask(NULL),
    m_state(StateStopped)
{
    if(ZORG_FAILURE(e))
	return;

    static unsigned streamId = 0;
    zorg_snprintf(LOGC, sizeof(LOGC) - 1, "zstrm%u", ++ streamId);
    LOGC[sizeof(LOGC) - 1] = 0;

    Hello cookedHello;

    cookedHello.type = MessageTypeHello;
    cookedHello.version = ProtocolVersion1_10;
    cookedHello.clientId; // TBD
    cookedHello.h3 = m_session->m_h3;
    cookedHello.zid = m_session->m_zid;
    cookedHello.streamFlags = m_flags;

    // TBD: optimize lists of components by removing trailing mandatory components
    cookedHello.hashAlgorithms = m_session->m_profile.hashAlgorithms;
    cookedHello.cipherAlgorithms = m_session->m_profile.cipherAlgorithms;
    cookedHello.authTagTypes = m_session->m_profile.authTagTypes;
    cookedHello.keyAgreementTypes = m_session->m_profile.keyAgreementTypes;
    cookedHello.sasTypes = m_session->m_profile.sasTypes;

    m_hello.setBody(e, formatHello(e, cookedHello, m_instance->m_implictHashFunction.get(), asBlob(m_session->m_h2), m_hello.body()));

    if(ZORG_FAILURE(e))
	return;

    m_session->m_streams.push_back(m_streamsEntry);
    ZORG_LOG(1,(LOGC, "attached to session %s", m_session->LOGC));
}

Stream::~Stream()
{
    mandatoryCleanup();
    detach();
    ZORG_LOG(1,(LOGC, "destroyed"));
}

::ZORG::ZRTP::Session * Stream::session() const { return m_session; }
StreamFlags Stream::flags() const { return m_flags; }

void Stream::detach()
{
    m_streamsEntry.remove();
    ZORG_LOG(1,(LOGC, "detached from session %s", m_session->LOGC));
}

void Stream::mandatoryCleanup()
{
    ZORG_DECL_ERROR(nonCritical);

    ZORG_CLEAR_ERROR(nonCritical);
    cancelSendMessage(nonCritical);
    assert(ZORG_SUCCESS(nonCritical));
}

void Stream::optionalCleanup()
{
    m_srtpSend.release();
    m_srtpRecv.release();
    m_hashFunction.release();
    m_cipherFunction.release();
    m_keyExchangeFunction.release();
    m_keyExchange.release();
}

void Stream::start(::ZORG::Error& e, const SSRC& ssrc)
{
    if(ZORG_FAILURE(e))
	return;

    if(m_state != StateStopped)
    {
	if(isFinalState(m_state))
	    ZORG_SET_ERROR(e, ErrorZRTPStopped);

	return;
    }

    m_ssrc = ssrc;
    m_instance->generateRandom(e, rawObjectAsBlob(m_sequenceNumber));

    sendMessage(e, LOGC, asBlob(m_hello), MessageTypeHello, m_instance->m_t1MaxRetransmit, m_instance->m_t1, m_instance->m_t1Cap);

    setState(e, LOGC, StateDiscovery);

    if(ZORG_ERROR_CODE(e) == ErrorInternalAbort)
	ZORG_CLEAR_ERROR(e);

    ZORG_LOG_SUCCESS(e,1,(LOGC, "started { ssrc: %u, initiator: %d, flags: { S: %u, M: %u, P: %u } }", asInt32_BE(m_ssrc), !!m_isInitiator, !!m_flags.signatureCapable, !!m_flags.mitm, !!m_flags.passive));
}

void Stream::stop()
{
    ZORG_LOG(2,(LOGC, "stopping..."));

    optionalCleanup();
    mandatoryCleanup();

    ZORG_DECL_ERROR(e);
    setState(e, LOGC, StateStopped);

    if(!ZORG_TEST_ABORT(e))
	assert(ZORG_SUCCESS(e));

    ZORG_LOG_SUCCESS(e,1,(LOGC, "stopped"));
}

void Stream::halt(::ZORG::Error& e, const ::ZORG::Error& stopError)
{
    ZORG_LOG(2,(LOGC, "terminating with local error %s...", "TODO"));

    switch(m_state)
    {
    case StateStopped:
    case StateNoZRTP:
    case StateLocalError:
    case StateError:
	ZORG_LOG(2,(LOGC, "termination ignored in state %s", getStateName(m_state)));
	return;

    default:
	ZORG_LOG(2,(LOGC, "cancelling all pending tasks"));
	m_session->m_iface->cancelAllTasks(); // TBD: multistream
	m_retransmitTask = NULL;

	ZORG_LOG(2,(LOGC, "notifying peer of local error"));
	sendError(e, LOGC, ZORG_ERROR_CODE(stopError));

	if(ZORG_SUCCESS(e))
	{
	    optionalCleanup();
	    m_localError = ZORG_ERROR_CODE(stopError);
	    setState(e, LOGC, StateLocalError);
	}
	else
	{
	    ZORG_UNREACHABLE();

	    ZORG_LOG(1,(LOGC, "could not notify peer of local error, shutting down"));

	    optionalCleanup();
	    mandatoryCleanup();

	    ZORG_DECL_ERROR(e2);
	    setState(e2, LOGC, StateError);
	    assert(ZORG_SUCCESS(e2));

	    if(ZORG_FAILURE(e2))
		ZORG_LOG(1,(LOGC, "error %s in critical path", "TODO"));
	}
    }
}

inline char hexDigit(int value)
{
    if(value >= 0 && value < 10)
	return '0' + value;
    else if(value >= 10 && value < 16)
	return 'A' + (value - 10);
    else
    {
	ZORG_UNREACHABLE();
	return 0;
    }
}

static const Blob SdpZrtpHashPrefix = asBlob("1.10 ");

const Blob& Stream::getSDPZrtpHash(::ZORG::Error& e, Blob& a)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    if(a.maxSize < SDP_HASH_ATTRIBUTE_BYTES)
	return NullBlob;

    if(m_state != StateStopped && isFinalState(m_state))
    {
	ZORG_SET_ERROR(e, ErrorZRTPStopped);
	return NullBlob;
    }

    BitArray<IMPLICIT_HASH_BITS> helloHash;
    m_instance->m_implictHashFunction->hash(e, m_hello.body(), asBlob(helloHash));

    if(ZORG_FAILURE(e))
	return NullBlob;

    BlobIterator p = beginBuffer(a);
    p = std::copy(beginData(SdpZrtpHashPrefix), endData(SdpZrtpHashPrefix), p);
    
    for(size_t i = 0; i < helloHash.BYTES; ++ i)
    {
	*p ++ = hexDigit((helloHash.bytes[i] & 0xf0) >> 4);
	*p ++ = hexDigit((helloHash.bytes[i] & 0x0f) >> 0);
    }

    assert((p - beginBuffer(a)) == SDP_HASH_ATTRIBUTE_BYTES);
    a.dataSize = SDP_HASH_ATTRIBUTE_BYTES;

    return a;
}

inline int parseHexDigit(::ZORG::Error& e, char value)
{
    if(ZORG_FAILURE(e))
	return -1;

    if(value >= '0' && value <= '9')
	return value - '0';
    else if(value >= 'A' && value <= 'F')
	return 10 + (value - 'A');
    else if(value >= 'a' && value <= 'f')
	return 10 + (value - 'a');
    else
    {
	ZORG_SET_ERROR(e, ErrorHexDigit);
	return -1;
    }
}

void Stream::setPeerSDPZrtpHash(::ZORG::Error& e, const Blob& a)
{
    if(ZORG_FAILURE(e))
	return;

    // wrong or unknown version: silently ignore
    if(a.dataSize < SdpZrtpHashPrefix.dataSize || !std::equal(beginData(SdpZrtpHashPrefix), endData(SdpZrtpHashPrefix), beginData(a)))
	return;

    // wrong length
    if(a.dataSize != SDP_HASH_ATTRIBUTE_BYTES)
    {
	ZORG_SET_ERROR(e, ErrorZRTPBadSDPAttribute);
	return;
    }

    BitArray<IMPLICIT_HASH_BITS> hashValue;
    const Blob hash = rightData(a, SDP_HASH_HEX_BYTES);
    assert(std::distance(beginData(hash), endData(hash)) == SDP_HASH_HEX_BYTES);

    BlobIterator p = beginData(hash);
    uint8_t * out = hashValue.bytes;

    for(; p != endData(hash); p += 2, ++ out)
	*out = (parseHexDigit(e, *(p + 0)) << 4) + parseHexDigit(e, *(p + 1));

    if(ZORG_FAILURE(e))
	return;

    m_expectedPeerHelloHash = hashValue;
    checkPeerHelloHash(e);
}

const Blob& Stream::protectRTP_InPlace(::ZORG::Error& e, Blob& rtpPacket)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    switch(m_state)
    {
    case StateStopped:
    case StateNoZRTP:
    case StateClear:
    case StateDiscovery:
    case StateDiscoveryWaitHello:
    case StateDiscoveryWaitHelloACK:
	return rtpPacket;

    case StateSecure:                 // Confirm2, Conf2ACK or SRTP media received
	assert(m_srtpSend.get());
	return m_srtpSend->protectRTP_InPlace(e, rtpPacket);

    case StateResponderKeyAgreement:  // Commit received
    case StateResponderConfirming:    // after receiving Commit
    case StateInitiatorKeyAgreement1: // Commit sent
    case StateInitiatorKeyAgreement2: // after sending Commit
    case StateInitiatorConfirming:    // after sending Commit
	m_instance->addEntropy(e, rtpPacket);
	return NullBlob;

    case StateError:
    case StateLocalError:
	return NullBlob;
	
    case StateUnknown:
	break;
    }

    ZORG_UNREACHABLE();
    return NullBlob;
}

const Blob& Stream::protectRTCP_InPlace(::ZORG::Error& e, Blob& rtcpPacket)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    switch(m_state)
    {
    case StateStopped:
    case StateNoZRTP:
    case StateClear:
    case StateDiscovery:
    case StateDiscoveryWaitHello:
    case StateDiscoveryWaitHelloACK:
	return rtcpPacket;

    case StateSecure:                 // Confirm2, Conf2ACK or SRTP media received
	assert(m_srtpSend.get());
	return m_srtpSend->protectRTCP_InPlace(e, rtcpPacket);

    case StateResponderKeyAgreement:  // Commit received
    case StateResponderConfirming:    // after receiving Commit
    case StateInitiatorKeyAgreement1: // Commit sent
    case StateInitiatorKeyAgreement2: // after sending Commit
    case StateInitiatorConfirming:    // after sending Commit
	return NullBlob;

    case StateError:
    case StateLocalError:
	return NullBlob;
	
    case StateUnknown:
	break;
    }

    ZORG_UNREACHABLE();
    return NullBlob;
}

const Blob& Stream::unprotectSRTP_InPlace(::ZORG::Error& e, Blob& srtpPacket)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    CookedMessage message;

    switch(cookMessage(e, LOGC, srtpPacket, message))
    {
    case MessageTypeUnknown:
	return NullBlob;

    case MessageTypeNone:
    default:
	return processMessage(e, srtpPacket, message);
    }
}

const Blob& Stream::unprotectSRTCP_InPlace(::ZORG::Error& e, Blob& srtcpPacket)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    switch(m_state)
    {
    case StateStopped:
    case StateNoZRTP:
    case StateClear:
    case StateDiscovery:
    case StateDiscoveryWaitHello:
    case StateDiscoveryWaitHelloACK:
	return srtcpPacket;

    case StateSecure:
	assert(m_srtpRecv.get());
	return m_srtpRecv->unprotectRTCP_InPlace(e, srtcpPacket);

    case StateResponderKeyAgreement:  // Commit received
    case StateResponderConfirming:    // after receiving Commit
    case StateInitiatorKeyAgreement1: // Commit sent
    case StateInitiatorKeyAgreement2: // after sending Commit
    case StateInitiatorConfirming:    // after sending Commit
	return NullBlob;

    case StateError:
    case StateLocalError:
	return NullBlob;
	
    case StateUnknown:
	break;
    }

    ZORG_UNREACHABLE();
    return NullBlob;
}

void Stream::run()
{
    m_retransmitTask = NULL;

    ZORG_DECL_ERROR(e);

    if(m_retransmitCounter == m_retransmitCap)
    {
	switch(m_state)
	{
	case StateDiscovery:
	case StateDiscoveryWaitHello:
	case StateDiscoveryWaitHelloACK:
	    optionalCleanup();
	    mandatoryCleanup();
	    // TBD: if we received a Hello, stay in StateDiscoveryWaitHelloACK
	    setState(e, LOGC, StateNoZRTP);
	    return;

	case StateLocalError:
	    optionalCleanup();
	    mandatoryCleanup();
	    setState(e, LOGC, StateError);
	    return;

	default:
	    halt(e, ErrorProtocolTimeout);
	    return;
	}
    }

    ZORG_LOG(3,(LOGC, "retransmitting %s [%u/%u]", getMessageTypeName(m_retransmitPacketType), m_retransmitCounter + 1, m_retransmitCap));

    sendMessage(e, LOGC, m_retransmitPacket);

    if(ZORG_SUCCESS(e))
    {
	++ m_retransmitCounter;

	if(m_retransmitTimer <= m_retransmitTimerCap / 2)
	    m_retransmitTimer *= 2;
	else
	    m_retransmitTimer = m_retransmitTimerCap;

	ZORG_LOG(3,(LOGC, "next retransmission of %s in %u milliseconds", getMessageTypeName(m_retransmitPacketType), m_retransmitTimer));
	m_retransmitTask = m_session->m_iface->runTask(e, this, m_retransmitTimer);
    }

    if(ZORG_FAILURE(e))
    {
	if(ZORG_ERROR_CODE(e) != ErrorInternalAbort)
	{
	    ZORG_DECL_ERROR(e2);
	    halt(e2, e);
	    return;
	}
    }
}

void Stream::cancel()
{
    // nothing to clean up
}

void Stream::cancelSendMessage(::ZORG::Error& e)
{
    if(ZORG_FAILURE(e))
	return;

    if(m_retransmitTask)
    {
	m_session->m_iface->cancelTask(e, m_retransmitTask);
        m_retransmitTask = NULL;

	if(ZORG_FAILURE(e))
	{
	    ZORG_DECL_ERROR(e2);
	    halt(e2, e);
	}
    }
}

void Stream::sendMessage(::ZORG::Error& e, const char * LOGC, const Blob& messagePacket)
{
    if(ZORG_FAILURE(e))
	return;

    assert(messagePacket.dataSize >= sizeof(CRC));

    formatMessagePacket(e, m_sequenceNumber ++, m_ssrc, leftData(messagePacket, - sizeof(CRC)), *static_cast<CRC *>(rightData(messagePacket, sizeof(CRC)).buffer));
    m_iface->sendMessage(e, this, messagePacket);
}

void Stream::sendMessage(::ZORG::Error& e, const char * LOGC, const Blob& messagePacket, MessageType messageType)
{
    if(ZORG_FAILURE(e))
	return;

    ZORG_LOG(3,(LOGC, "sending %s (%u bytes)", getMessageTypeName(messageType), messagePacket.dataSize));
    sendMessage(e, LOGC, messagePacket);
}

void Stream::sendMessage(::ZORG::Error& e, const char * LOGC, const Blob& messagePacket, MessageType messageType, unsigned counter, int timer, int timerCap)
{
    if(ZORG_FAILURE(e))
	return;

    ZORG_LOG(3,(LOGC, "sending %s (%u bytes); retransmit %u times, initial delay %u, maximum delay %u", getMessageTypeName(messageType), messagePacket.dataSize, counter, timer, timerCap));

    assert(m_retransmitTask == NULL);

    if(m_retransmitTask)
    {
	m_session->m_iface->cancelTask(e, m_retransmitTask);
	assert(ZORG_SUCCESS(e));
	m_retransmitTask = NULL;
    }

    m_retransmitPacket = messagePacket;
    m_retransmitPacketType = messageType;
    m_retransmitCounter = 0;
    m_retransmitCap = counter;
    m_retransmitTimer = timer;
    m_retransmitTimerCap = timerCap;

    sendMessage(e, LOGC, m_retransmitPacket);
    m_retransmitTask = m_session->m_iface->runTask(e, this, m_retransmitTimer);
}

void Stream::notifyProtocolEvent(::ZORG::Error& e, const char * LOGC, Event evt)
{
    if(ZORG_FAILURE(e))
	return;

    bool oldIsFinalState = isFinalState(m_state);

    ZORG_LOG(3,(LOGC, "notifying protocol event %s in state %s", getEventName(evt), getStateName(m_state)));
    m_iface->onProtocolEvent(this, evt);

    if(isFinalState(m_state) && !oldIsFinalState)
	ZORG_SET_ERROR(e, ErrorInternalAbort);
}

void Stream::notifySecurityEvent(::ZORG::Error& e, const char * LOGC, SecurityEvent evt)
{
    if(ZORG_FAILURE(e))
	return;

    bool oldIsFinalState = isFinalState(m_state);

    ZORG_LOG(3,(LOGC, "notifying security event %s in state %s", getSecurityEventName(evt), getStateName(m_state)));
    m_iface->onSecurityEvent(this, evt);

    if(isFinalState(m_state) && !oldIsFinalState)
	ZORG_SET_ERROR(e, ErrorInternalAbort);
}

Crypto::RFC5764::SRTPProfile Stream::getRTPProfile(::ZORG::Error& e) const
{
    if(ZORG_FAILURE(e))
	return Crypto::RFC5764::SRTP_UnknownProfile;

    if(m_activeProfile.cipherAlgorithm == CipherAES1)
    {
	if(m_activeProfile.authTagType == AuthTagHS32)
	    return Crypto::RFC5764::SRTP_AES128_CM_HMAC_SHA1_32;
	else if(m_activeProfile.authTagType == AuthTagHS80)
	    return Crypto::RFC5764::SRTP_AES128_CM_HMAC_SHA1_80;
    }
    else if(m_activeProfile.cipherAlgorithm == CipherAES3)
    {
	if(m_activeProfile.authTagType == AuthTagHS32)
	    return Crypto::RFC5764::SRTP_AES256_CM_HMAC_SHA1_32;
	else if(m_activeProfile.authTagType == AuthTagHS80)
	    return Crypto::RFC5764::SRTP_AES256_CM_HMAC_SHA1_80;
    }

    ZORG_SET_ERROR(e, ErrorZRTPBadSRTPProfile);
    return Crypto::RFC5764::SRTP_UnknownProfile;
}

Crypto::RFC5764::SRTPProfile Stream::getRTCPProfile(::ZORG::Error& e) const
{
    return getRTPProfile(e);
}

const Words<2>& bodyMAC(const Blob& body)
{
    assert(body.dataSize % WORD_BYTES == 0);
    assert(body.dataSize >= sizeof(Words<2>));

    return *reinterpret_cast<Words<2> *>(static_cast<uint8_t *>(body.buffer) + (body.dataSize - sizeof(Words<2>)));
}

Blob bodyWithoutMAC(const Blob& body)
{
    assert(body.dataSize % WORD_BYTES == 0);
    assert(body.dataSize >= sizeof(Words<2>));

    Blob withoutMAC = body;
    withoutMAC.dataSize -= sizeof(Words<2>);
    return withoutMAC;
}

bool resolveCommitContention(::ZORG::Error& e, KeyAgreementType keyAgreementType, KeyAgreementType peerKeyAgreementType, bool mitm, bool peerMitm, const Blob& unique, const Blob& peerUnique)
{
    if(ZORG_FAILURE(e))
	return false;

    if((keyAgreementType == KeyAgreementMult) != (peerKeyAgreementType == KeyAgreementMult))
    {
	ZORG_SET_ERROR(e, ErrorZRTPBadMultistream);
	return false;
    }

    bool isDH = isKeyAgreementDH(keyAgreementType);
    bool peerIsDH = isKeyAgreementDH(peerKeyAgreementType);

    if(isDH && peerKeyAgreementType == KeyAgreementPrsh)
	return true;

    if(keyAgreementType == KeyAgreementPrsh && peerIsDH)
	return false;

    if(keyAgreementType == KeyAgreementPrsh && peerKeyAgreementType == KeyAgreementPrsh)
    {
	if(mitm && !peerMitm)
	    return false;

	if(!mitm && peerMitm)
	    return true;
    }

    if((isDH && peerIsDH) || (!isDH && !peerIsDH))
    {
	if(unique.dataSize < peerUnique.dataSize)
	    return true;

	if(unique.dataSize > peerUnique.dataSize)
	    return false;

	int cmp = memcmp(unique.buffer, peerUnique.buffer, peerUnique.dataSize);

	if(cmp > 0)
	    return true;

	if(cmp < 0)
	    return false;

	ZORG_SET_ERROR(e, asErrorCode(ErrorNonceReuse));
	return false;
    }

    ZORG_UNREACHABLE_E(e);
    return false;
}

void Stream::sendACK(::ZORG::Error& e, const char * LOGC, MessageType messageType)
{
    if(ZORG_FAILURE(e))
	return;

    RawMessageFixedBuffer_T<RawMessageBody> ack;

    switch(messageType)
    {
    default:
	ZORG_UNREACHABLE_E(e);
	return;

    case MessageTypeHelloACK:
    case MessageTypeConf2ACK:
    case MessageTypeErrorACK:
    case MessageTypeClearACK:
    case MessageTypeRelayACK:
	ack.setBody(e, formatEmptyMessage(e, messageType, ack.body()));
	break;
    }

    sendMessage(e, LOGC, asBlob(ack), messageType);
}

void Stream::sendError(::ZORG::Error& e, const char * LOGC, ::ZORG::ErrorCode stopErrorCode)
{
    if(ZORG_FAILURE(e))
	return;

    Error error;
    error.errorCode = toProtocolError(stopErrorCode);
    
    m_error.setBody(e, formatError(e, error, m_error.body()));
    sendMessage(e, LOGC, asBlob(m_error), MessageTypeError, m_instance->m_t2MaxRetransmit, m_instance->m_t2, m_instance->m_t2Cap);
}

void Stream::calculatePeerHelloHash(::ZORG::Error& e, const Blob& peerHello)
{
    if(ZORG_FAILURE(e))
	return;

    m_instance->m_implictHashFunction->hash(e, peerHello, m_peerHelloHash);
    checkPeerHelloHash(e);
}

void Stream::checkPeerHelloHash(::ZORG::Error& e)
{
    if(ZORG_FAILURE(e))
	return;

    if(!m_expectedPeerHelloHash.dataSize)
	return;

    if(!m_peerHelloHash.dataSize)
	return;

    assert(m_expectedPeerHelloHash.dataSize == m_peerHelloHash.dataSize);

    if(m_expectedPeerHelloHash.dataSize != m_peerHelloHash.dataSize)
    {
	ZORG_SET_ERROR(e, ErrorInternal);
	return;
    }

    if(m_expectedPeerHelloHash != m_peerHelloHash)
	notifySecurityEvent(e, LOGC, SecurityEventBadHelloHash);
}

void Stream::handleHello(::ZORG::Error& e, const char * LOGC, Blob& rawMessage, const CookedMessage& message)
{
    if(ZORG_FAILURE(e))
	return;

    calculatePeerHelloHash(e, message.messageBody);

    Hello hello;
    cookHello(e, LOGC, message.messageBody, hello);

    if(ZORG_FAILURE(e))
	return;

    // FIXME: here we assume any unrecognized version is a later version
    if(hello.version == ProtocolVersionUnsupported)
	return;

    // we are not the initiator, and the other peer is passive: the handshake will never end, therefore abort
    if(!m_isInitiator && hello.streamFlags.passive)
    {
	ZORG_SET_ERROR(e, asErrorCode(ErrorServiceUnavailable));
	return;
    }

    // ZIDs must be unique
    if(m_session->m_zid == hello.zid)
    {
	ZORG_SET_ERROR(e, asErrorCode(ErrorZIDCollision));
	return;
    }

    KeyAgreementTypeList intersectingKeyAgreementTypesMine = m_session->m_profile.keyAgreementTypes & (hello.keyAgreementTypes | MANDATORY_KEY_AGREEMENT_TYPES);
    KeyAgreementTypeList intersectingKeyAgreementTypesTheirs = (hello.keyAgreementTypes | MANDATORY_KEY_AGREEMENT_TYPES) & m_session->m_profile.keyAgreementTypes;

    if(!intersectingKeyAgreementTypesMine)
    {
	ZORG_SET_ERROR(e, asErrorCode(ErrorHelloComponentsMismatch));
	return;
    }

    assert(intersectingKeyAgreementTypesMine);
    assert(intersectingKeyAgreementTypesTheirs);

    HashAlgorithmList intersectingHashAlgorithms = m_session->m_profile.hashAlgorithms & (hello.hashAlgorithms | MANDATORY_HASH_ALGORITHMS);
    CipherAlgorithmList intersectingCipherAlgorithms = m_session->m_profile.cipherAlgorithms & (hello.cipherAlgorithms | MANDATORY_CIPHER_ALGORITHMS);
    AuthTagTypeList intersectingAuthTagTypes = m_session->m_profile.authTagTypes & (hello.authTagTypes | MANDATORY_AUTH_TAG_TYPES);
    SASTypeList intersectingSasTypes = m_session->m_profile.sasTypes & (hello.sasTypes | MANDATORY_SAS_TYPES);

    if(!intersectingHashAlgorithms)
    {
	ZORG_SET_ERROR(e, asErrorCode(ErrorHelloComponentsMismatch));
	return;
    }

    if(!intersectingCipherAlgorithms)
    {
	ZORG_SET_ERROR(e, asErrorCode(ErrorHelloComponentsMismatch));
	return;
    }

    if(!intersectingAuthTagTypes)
    {
	ZORG_SET_ERROR(e, asErrorCode(ErrorHelloComponentsMismatch));
	return;
    }

    if(!intersectingSasTypes)
    {
	ZORG_SET_ERROR(e, asErrorCode(ErrorHelloComponentsMismatch));
	return;
    }

    // TBD: Mult, Prsh
    assert(isKeyAgreementDH(*intersectingKeyAgreementTypesMine.begin()));
    assert(isKeyAgreementDH(*intersectingKeyAgreementTypesTheirs.begin()));

    KeyAgreementType keyAgreementType = fasterDHKeyAgreementType(e, *intersectingKeyAgreementTypesMine.begin(), *intersectingKeyAgreementTypesTheirs.begin());

    if(ZORG_FAILURE(e))
	return;

    if(m_isInitiator)
    {
	// FIXME: pick a combination that can be represented as a standard SRTP profile
	CipherAlgorithm cipherAlgorithm = *intersectingCipherAlgorithms.begin();
	AuthTagType authTagType = *intersectingAuthTagTypes.begin();

	if(keyAgreementType == KeyAgreementEC38)
	{
	    HashAlgorithmList::const_iterator p = intersectingHashAlgorithms.begin();
	    HashAlgorithmList::const_iterator end = intersectingHashAlgorithms.end();

	    for(; p != end; ++ p)
	    {
		if(*p == Zorg_HashS384 || *p == Zorg_HashN384)
		{
		    m_activeProfile.hashAlgorithm = *p;
		    break;
		}
	    }

	    if(p == end)
	    {
		ZORG_SET_ERROR(e, asErrorCode(ErrorHelloComponentsMismatch));
		return;
	    }
	}
	else
    	    m_activeProfile.hashAlgorithm = *intersectingHashAlgorithms.begin();

	m_activeProfile.cipherAlgorithm = cipherAlgorithm;
	m_activeProfile.authTagType = authTagType;
	m_activeProfile.sasType = *intersectingSasTypes.begin();

	m_hashFunction.reset(m_instance->m_cryptoSuite->createHashFunction(e, m_activeProfile.hashAlgorithm));
	m_cipherFunction.reset(m_instance->m_cryptoSuite->createCipherFunction(e, m_activeProfile.cipherAlgorithm));
    }

    m_activeProfile.keyAgreementType = keyAgreementType;

    m_keyExchangeFunction.reset(m_instance->m_cryptoSuite->createKeyAgreementFunction(e, m_activeProfile.keyAgreementType, m_instance));

    if(ZORG_FAILURE(e))
	return;

    m_keyExchange.reset(m_keyExchangeFunction->Create(e));
    m_keyExchange->getPublicKey(e, m_pv); // FIXME: send helloACK first

    m_peerH3 = hello.h3;

    m_session->m_peerZid = hello.zid; // TBD: multistream
    m_session->m_peerZidAvailable = true;
    ZORG_LOG(1,(LOGC, "peer zid is %s", ZORG_HEX_LINE_DUMP(m_session->m_peerZid)));

    m_peerFlags = hello.streamFlags;
    // TBD: store client id

    m_peerHello.copyBody(message.messageBody);

    // TBD: implement fast acknowledgment (send Commit instead of HelloACK)

    sendACK(e, LOGC, MessageTypeHelloACK);

    if(ZORG_FAILURE(e))
	return;

    m_session->lookupCache();

    // TBD: extend Hello retry schedule to at least 12 seconds
}

Stream::State Stream::discoveryDone(::ZORG::Error& e, const char * LOGC)
{
    if(ZORG_FAILURE(e))
	return StateUnknown;

    if(m_isInitiator)
    {
	m_totalHash.reset(m_hashFunction->Create(e));
	m_totalHash->next(e, m_peerHello.body());

	if(m_session->m_rs1.dataSize)
	{
	    truncatedCopy(e, m_hashFunction->mac(e, m_session->m_rs1, asBlob("Initiator"), asBlob(BitArray<MAX_MAC_BITS>())), asBlob(m_session->m_rs1ID));
	    truncatedCopy(e, m_hashFunction->mac(e, m_session->m_rs1, asBlob("Responder"), asBlob(BitArray<MAX_MAC_BITS>())), asBlob(m_session->m_peerRS1ID));
	    ZORG_DUMP_VARIABLE(e, "rs1IDr", m_session->m_peerRS1ID);
	}
	else
	    m_instance->generateRandom(e, asBlob(m_session->m_rs1ID));

	ZORG_DUMP_VARIABLE(e, "rs1IDi", m_session->m_rs1ID);

	if(m_session->m_rs2.dataSize)
	{
	    truncatedCopy(e, m_hashFunction->mac(e, m_session->m_rs2, asBlob("Initiator"), asBlob(BitArray<MAX_MAC_BITS>())), asBlob(m_session->m_rs2ID));
	    truncatedCopy(e, m_hashFunction->mac(e, m_session->m_rs2, asBlob("Responder"), asBlob(BitArray<MAX_MAC_BITS>())), asBlob(m_session->m_peerRS2ID));
	    ZORG_DUMP_VARIABLE(e, "rs2IDr", m_session->m_peerRS2ID);
	}
	else
	    m_instance->generateRandom(e, asBlob(m_session->m_rs2ID));

	ZORG_DUMP_VARIABLE(e, "rs2IDi", m_session->m_rs2ID);

	if(m_pv.dataSize == 0)
	    m_keyExchange->getPublicKey(e, m_pv);

	ZORG_DUMP_VARIABLE(e, "pvi", m_pv);

	// pre-calculate our DHPart2
	DHPart2 dhPart2;
	dhPart2.h1 = m_session->m_h1;
	dhPart2.rs1IDi = m_session->m_rs1ID;
	dhPart2.rs2IDi = m_session->m_rs2ID;
	m_instance->generateRandom(e, asBlob(dhPart2.auxsecretIDi));
	m_instance->generateRandom(e, asBlob(dhPart2.pbxsecretIDi));
	dhPart2.pvi = m_pv;

	m_dhPart2.setBody(e, formatDHPart2(e, dhPart2, m_instance->m_implictHashFunction.get(), m_activeProfile.keyAgreementType, asBlob(m_session->m_h0), m_dhPart2.body()));
    }

    if(m_isInitiator && m_session->m_profile.autoSecure && !m_flags.passive)
    {
	// TBD: this needs to be a function, for fast acknowledge and manual "go secure"
	Commit commit;

	commit.h2 = m_session->m_h2;
	commit.zid = m_session->m_zid;
	commit.hashAlgorithm = m_activeProfile.hashAlgorithm;
	commit.cipherAlgorithm = m_activeProfile.cipherAlgorithm;
	commit.authTagType = m_activeProfile.authTagType;
	commit.keyAgreementType = m_activeProfile.keyAgreementType;
	commit.sasType = m_activeProfile.sasType;
	commit.kaparam.dh.hvi = calculateHvi(e, m_hashFunction.get(), m_dhPart2.body(), m_peerHello.body()); // FIXME: hardcoded for DH mode

	m_hvi = commit.kaparam.dh.hvi;

	m_commit.setBody(e, formatCommit(e, commit, m_instance->m_implictHashFunction.get(), asBlob(m_session->m_h1), m_commit.body()));
	m_totalHash->next(e, m_commit.body());

	sendMessage(e, LOGC, asBlob(m_commit), MessageTypeCommit, m_instance->m_t2MaxRetransmit, m_instance->m_t2, m_instance->m_t2Cap);

	return StateInitiatorKeyAgreement1;
    }
    else
	return StateClear;
}

Stream::State Stream::secureDone(::ZORG::Error& e, const char * LOGC)
{
    if(ZORG_FAILURE(e))
	return StateUnknown;

    // TBD: multistream

    m_session->m_cacheMismatch = m_session->m_rs1.dataSize && !m_session->m_s1.dataSize;

    if(m_session->m_cacheMismatch)
	notifySecurityEvent(e, LOGC, SecurityEventCacheMismatch);

    if(isKeyAgreementDH(m_activeProfile.keyAgreementType))
	m_session->m_rs2 = m_session->m_rs1;

    KDF(e, m_hashFunction.get(), m_s0, asBlob("retained secret"), m_kdfContext, 256, m_session->m_rs1);

    m_session->updateCache();

    wipeData(m_s0);

    return StateSecure;
}

Stream::State Stream::handleCommit(::ZORG::Error& e, const char * LOGC, Blob& rawMessage, const CookedMessage& message)
{
    if(ZORG_FAILURE(e))
	return StateUnknown;

    assert(message.messageType == MessageTypeCommit);

    Commit commit;
    cookCommit(e, LOGC, message.messageBody, commit);

    if(ZORG_FAILURE(e))
	return StateUnknown;

    if(commit.zid != m_session->m_peerZid)
    {
	ZORG_SET_ERROR(e, asErrorCode(ErrorMalformedPacket));
	return StateUnknown;
    }

    if(m_isInitiator)
    {
	// we have sent our Commit, see if we should keep being the initiator
	if(m_state == StateInitiatorKeyAgreement1)
	{
	    // FIXME: hardcoded for DH mode
	    Blob unique = asBlob(m_hvi);

	    Blob peerUnique;

	    switch(commit.keyAgreementType)
	    {
	    case KeyAgreementMult:
		peerUnique = asBlob(commit.kaparam.mult.nonce);
		break;

	    case KeyAgreementPrsh:
		peerUnique = asBlob(commit.kaparam.prsh.nonce);
		break;

	    default:
		peerUnique = asBlob(commit.kaparam.dh.hvi);
		break;

	    case KeyAgreementUnknown:
		ZORG_UNREACHABLE_E(e);
		return StateUnknown;
	    }

	    bool isInitiator = resolveCommitContention(e, m_activeProfile.keyAgreementType, commit.keyAgreementType, m_flags.mitm, m_peerFlags.mitm, unique, peerUnique);

	    if(ZORG_FAILURE(e))
		return StateUnknown;

	    m_isInitiator = isInitiator;
	}
	// we didn't send our Commit yet, we'll be the responder
	else
	    m_isInitiator = false;
    }

    // drop the Commit, we are the initiator
    if(m_isInitiator)
	return StateUnknown;

    // verify the HMAC of the peer's Hello
    const Words<2>& expectedHelloMAC = bodyMAC(m_peerHello.body());
    Words<2> actualHelloMAC;

    truncatedCopy(e, m_instance->m_implictHashFunction->mac(e, asBlob(commit.h2), bodyWithoutMAC(m_peerHello.body()), asBlob(BitArray<IMPLICIT_MAC_BITS>())), asBlob(actualHelloMAC));

    if(actualHelloMAC != expectedHelloMAC)
	notifySecurityEvent(e, LOGC, SecurityEventBadMessageMAC);

    // verify that the received H2 is consistent with the H3 we received in Hello
    Words<8> actualH3;
    truncatedCopy(e, m_instance->m_implictHashFunction->hash(e, asBlob(commit.h2), asBlob(BitArray<MAX_HASH_BITS>())), asBlob(actualH3));

    if(ZORG_FAILURE(e))
	return StateUnknown;

    if(actualH3 != m_peerH3)
    {
	ZORG_SET_ERROR(e, ErrorZRTPWrongHashImage);
	return StateUnknown;
    }

    m_peerCommit.copyBody(message.messageBody);
    m_peerH2 = commit.h2;
    m_peerHvi = commit.kaparam.dh.hvi; // FIXME: hardcoded for DH mode

    // stop sending Hello
    cancelSendMessage(e);

    if(!m_session->m_profile.keyAgreementTypes[commit.keyAgreementType])
    {
	ZORG_SET_ERROR(e, asErrorCode(ErrorPublicKeyExchangeNotSupported));
	return StateUnknown;
    }

    if(!m_session->m_profile.hashAlgorithms[commit.hashAlgorithm])
    {
	ZORG_SET_ERROR(e, asErrorCode(ErrorHashTypeNotSupported));
	return StateUnknown;
    }

    if(!m_session->m_profile.cipherAlgorithms[commit.cipherAlgorithm])
    {
	ZORG_SET_ERROR(e, asErrorCode(ErrorCipherTypeNotSupported));
	return StateUnknown;
    }

    if(!m_session->m_profile.authTagTypes[commit.authTagType])
    {
	ZORG_SET_ERROR(e, asErrorCode(ErrorCipherTypeNotSupported));
	return StateUnknown;
    }

    if(!m_session->m_profile.sasTypes[commit.sasType])
    {
	ZORG_SET_ERROR(e, asErrorCode(ErrorSASSchemeNotSupported));
	return StateUnknown;
    }

    if(commit.keyAgreementType != m_activeProfile.keyAgreementType)
    {
	m_keyExchangeFunction.reset(m_instance->m_cryptoSuite->createKeyAgreementFunction(e, commit.keyAgreementType, m_instance));

	if(ZORG_SUCCESS(e))
	{
	    m_keyExchange.reset(m_keyExchangeFunction->Create(e));

	    if(ZORG_SUCCESS(e))
		m_keyExchange->getPublicKey(e, m_pv);
	}

	if(ZORG_SUCCESS(e))
	    m_activeProfile.keyAgreementType = commit.keyAgreementType;
    }

    if(ZORG_FAILURE(e))
	return StateUnknown;

    m_activeProfile.hashAlgorithm = commit.hashAlgorithm;
    m_activeProfile.cipherAlgorithm = commit.cipherAlgorithm;
    m_activeProfile.authTagType = commit.authTagType;
    m_activeProfile.sasType = commit.sasType;

    m_hashFunction.reset(m_instance->m_cryptoSuite->createHashFunction(e, m_activeProfile.hashAlgorithm));
    m_cipherFunction.reset(m_instance->m_cryptoSuite->createCipherFunction(e, m_activeProfile.cipherAlgorithm));

    m_totalHash.reset(m_hashFunction->Create(e));
    m_totalHash->next(e, m_hello.body());
    m_totalHash->next(e, message.messageBody);

    if(m_session->m_rs1.dataSize)
    {
	truncatedCopy(e, m_hashFunction->mac(e, m_session->m_rs1, asBlob("Responder"), asBlob(BitArray<MAX_MAC_BITS>())), asBlob(m_session->m_rs1ID));
	truncatedCopy(e, m_hashFunction->mac(e, m_session->m_rs1, asBlob("Initiator"), asBlob(BitArray<MAX_MAC_BITS>())), asBlob(m_session->m_peerRS1ID));
	ZORG_DUMP_VARIABLE(e, "rs1IDi", m_session->m_peerRS1ID);
    }
    else
	m_instance->generateRandom(e, asBlob(m_session->m_rs1ID));

    ZORG_DUMP_VARIABLE(e, "rs1IDr", m_session->m_rs1ID);

    if(m_session->m_rs2.dataSize)
    {
	truncatedCopy(e, m_hashFunction->mac(e, m_session->m_rs2, asBlob("Responder"), asBlob(BitArray<MAX_MAC_BITS>())), asBlob(m_session->m_rs2ID));
	truncatedCopy(e, m_hashFunction->mac(e, m_session->m_rs2, asBlob("Initiator"), asBlob(BitArray<MAX_MAC_BITS>())), asBlob(m_session->m_peerRS2ID));
	ZORG_DUMP_VARIABLE(e, "rs2IDi", m_session->m_peerRS2ID);
    }
    else
	m_instance->generateRandom(e, asBlob(m_session->m_rs2ID));

    ZORG_DUMP_VARIABLE(e, "rs2IDr", m_session->m_rs1ID);

    if(m_pv.dataSize == 0)
	m_keyExchange->getPublicKey(e, m_pv);

    ZORG_DUMP_VARIABLE(e, "pvr", m_pv);

    DHPart1 dhPart1;
    dhPart1.h1 = m_session->m_h1;
    dhPart1.rs1IDr = m_session->m_rs1ID;
    dhPart1.rs2IDr = m_session->m_rs2ID;
    m_instance->generateRandom(e, asBlob(dhPart1.auxsecretIDr));
    m_instance->generateRandom(e, asBlob(dhPart1.pbxsecretIDr));
    dhPart1.pvr = m_pv;

    m_dhPart1.setBody(e, formatDHPart1(e, dhPart1, m_instance->m_implictHashFunction.get(), m_activeProfile.keyAgreementType, asBlob(m_session->m_h0), m_dhPart1.body()));
    m_totalHash->next(e, m_dhPart1.body());
    sendMessage(e, LOGC, asBlob(m_dhPart1), MessageTypeDHPart1);

    return StateResponderKeyAgreement;
}

const Blob& Stream::processMessage(::ZORG::Error& e, Blob& rawMessage, const CookedMessage& message)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    char LOGC[LOGGING_CONTEXT_SIZE];
    zorg_snprintf(LOGC, sizeof(LOGC) - 1, "zmess%u", message.sequenceNumber);
    LOGC[sizeof(LOGC) - 1] = 0;

    if(message.messageType != MessageTypeNone || m_state == StateInitiatorConfirming)
	ZORG_LOG(3,(LOGC, "handling %s in state %s on stream %s", getMessageTypeName(message.messageType), getStateName(m_state), this->LOGC));

    bool unhandled = false;
    State newState = StateUnknown;

    // handle Ping
    if(message.messageType == MessageTypePing)
    {
	Ping cookedPing;
	cookPing(e, LOGC, message.messageBody, cookedPing);

	if(ZORG_SUCCESS(e))
	{
	    PingACK cookedPingACK;

	    cookedPingACK.type = MessageTypePingACK;
	    cookedPingACK.version = ProtocolVersion1_10;
	    cookedPingACK.senderEndpointHash;
	    cookedPingACK.receivedEndpointHash = cookedPing.endpointHash;
	    cookedPingACK.receivedSSRC = message.ssrc;

	    // TBD: format and send message
	}

	goto l_Epilog;
    }

    // handle error
    if(message.messageType == MessageTypeError)
    {
	switch(m_state)
	{
	case StateStopped:
	case StateNoZRTP:
	    unhandled = true;
	    break;

	case StateError:
	case StateClear:
	case StateSecure:
	case StateLocalError:
	case StateDiscovery:
	case StateDiscoveryWaitHello:
	case StateDiscoveryWaitHelloACK:
	case StateResponderKeyAgreement:
	case StateResponderConfirming:
	case StateInitiatorKeyAgreement1:
	case StateInitiatorKeyAgreement2:
	case StateInitiatorConfirming:
	    {
		Error cookedError;
		cookError(e, LOGC, message.messageBody, cookedError);

		if(ZORG_SUCCESS(e))
		{
		    m_remoteError = asErrorCode(cookedError.errorCode);

		    ZORG_DECL_ERROR(nonFatal);
		    sendACK(nonFatal, LOGC, MessageTypeErrorACK);

		    if(m_state != StateError)
		    {
			optionalCleanup();
			mandatoryCleanup();
			newState = StateError;
			ZORG_LOG(1,(LOGC, "termination due to remote error 0x%X", cookedError.errorCode));
		    }
		}
	    }

	    break;

	case StateUnknown:
	default:
	    ZORG_UNREACHABLE_E(e);
	    break;
	}

	goto l_Epilog;
    }

    // validate empty messages
    switch(message.messageType)
    {
    case MessageTypeHelloACK:
    case MessageTypeConf2ACK:
    case MessageTypeErrorACK:
    case MessageTypeClearACK:
    case MessageTypeRelayACK:
	{
	    Message cookedEmptyMessage;
	    cookEmptyMessage(e, LOGC, message.messageBody, cookedEmptyMessage, message.messageType);

	    if(ZORG_FAILURE(e))
		goto l_Epilog;
	}

	break;

    default:
	break;
    }

    switch(m_state)
    {
    case StateStopped:
    case StateNoZRTP:
	unhandled = true;
	break;

    case StateClear:
	switch(message.messageType)
	{
	case MessageTypeHello:
	    sendACK(e, LOGC, MessageTypeHelloACK);
	    break;

	case MessageTypeCommit:
	    newState = handleCommit(e, LOGC, rawMessage, message);
	    break;

	default:
	    unhandled = true;
	    break;
	}

	break;

    case StateSecure:
	unhandled = true;
	break;

    case StateError:
	// drop everything until the state is cleared with stop()
	unhandled = true;
	break;

    case StateLocalError:
	switch(message.messageType)
	{
	case MessageTypeErrorACK:
	    cancelSendMessage(e);
	    newState = StateError;
	    break;

	default:
	    unhandled = true;
	    break;
	}

	break;

    case StateDiscovery:
	switch(message.messageType)
	{
	case MessageTypeHello:
	    handleHello(e, LOGC, rawMessage, message);
	    newState = StateDiscoveryWaitHelloACK;
	    break;

	case MessageTypeHelloACK:
	    cancelSendMessage(e);
	    newState = StateDiscoveryWaitHello;
	    break;

	default:
	    unhandled = true;
	    break;
	}

	break;

    case StateDiscoveryWaitHello:
	switch(message.messageType)
	{
	case MessageTypeHello:
	    handleHello(e, LOGC, rawMessage, message);
	    newState = discoveryDone(e, LOGC);
	    break;

	default:
	    unhandled = true;
	    break;
	}

	break;

    case StateDiscoveryWaitHelloACK:
	switch(message.messageType)
	{
	case MessageTypeHelloACK:
	    cancelSendMessage(e);
	    newState = discoveryDone(e, LOGC);
	    break;

	case MessageTypeCommit:
	    cancelSendMessage(e);
	    newState = handleCommit(e, LOGC, rawMessage, message);
	    break;

	default:
	    unhandled = true;
	    break;
	}

	break;

    case StateResponderKeyAgreement:
	switch(message.messageType)
	{
	case MessageTypeCommit:
	    sendMessage(e, LOGC, asBlob(m_dhPart1), MessageTypeDHPart1);
	    break;

	case MessageTypeDHPart2:
	    {
		DHPart2 dhPart2;
		cookDHPart2(e, LOGC, message.messageBody, m_activeProfile.keyAgreementType, dhPart2);

		// verify MAC of peer's Commit
		Words<2> actualCommitMAC;
		const Words<2>& expectedCommitMAC = bodyMAC(m_peerCommit.body());

		truncatedCopy(e, m_instance->m_implictHashFunction->mac(e, asBlob(dhPart2.h1), bodyWithoutMAC(m_peerCommit.body()), asBlob(BitArray<IMPLICIT_MAC_BITS>())), asBlob(actualCommitMAC));

		if(ZORG_FAILURE(e))
		    break;

		if(actualCommitMAC != expectedCommitMAC)
		    notifySecurityEvent(e, LOGC, SecurityEventBadMessageMAC);

		// check that H1 is consistent with H2
		Words<8> actualH2;
		truncatedCopy(e, m_instance->m_implictHashFunction->hash(e, asBlob(dhPart2.h1), asBlob(BitArray<IMPLICIT_MAC_BITS>())), asBlob(actualH2));

		if(ZORG_FAILURE(e))
		    break;

		if(actualH2 != m_peerH2)
		{
		    ZORG_SET_ERROR(e, ErrorZRTPWrongHashImage);
		    break;
		}

		// check that the pvi is not an insecure value
		checkPV(e, dhPart2.pvi, m_activeProfile.keyAgreementType);

		if(ZORG_FAILURE(e))
		    break;

		// calculate hvi and compare with the value received in the Commit message
		Words<8> hvi = calculateHvi(e, m_hashFunction.get(), message.messageBody, m_hello.body());

		if(ZORG_FAILURE(e))
		    break;

		if(hvi != m_peerHvi)
		{
		    ZORG_SET_ERROR(e, asErrorCode(ErrorDHHVIMismatch));
		    break;
		}

		m_peerDHPart2.copyBody(message.messageBody);
		m_peerH1 = dhPart2.h1;

		// finish calculating total_hash
		m_totalHash->next(e, message.messageBody);
		m_totalHash->finish(e, m_totalHashValue);
		m_totalHash.release();
		ZORG_DUMP_VARIABLE(e, "total_hash", m_totalHashValue);

		// calculate KDF_Context
		memcpy(m_kdfContext.bytes, m_session->m_peerZid.bytes, ZID::BYTES);
		memcpy(m_kdfContext.bytes + ZID::BYTES, m_session->m_zid.bytes, ZID::BYTES);
		memcpy(m_kdfContext.bytes + ZID::BYTES + ZID::BYTES, m_totalHashValue.buffer, m_totalHashValue.dataSize);
		m_kdfContext.dataSize = ZID::BYTES + ZID::BYTES + m_totalHashValue.dataSize;
		ZORG_DUMP_VARIABLE(e, "KDF_Context", m_kdfContext);

		// calculate s1
		ZORG_DUMP_VARIABLE(e, "rs1IDi", dhPart2.rs1IDi);
		ZORG_DUMP_VARIABLE(e, "rs2IDi", dhPart2.rs2IDi);

		bool continuityLost = false;
		calculateS1(e, m_session->m_rs1, m_session->m_rs2, m_session->m_peerRS1ID, m_session->m_peerRS2ID, dhPart2.rs1IDi, dhPart2.rs2IDi, m_session->m_s1, continuityLost);
		ZORG_DUMP_VARIABLE(e, "s1", m_session->m_s1);

		// loss of continuity with the previous session: we can no longer trust the previous value of the SAS verified flag
		if(ZORG_SUCCESS(e) && continuityLost)
		{
		    ZORG_LOG(1,(LOGC, "previous session lost: resetting V flag"));
		    m_session->setSASVerifiedInternal(false);
		}

		// key exchange
		BitBlob<MAX_PV_BITS> dhResult;

		m_keyExchange->agree(e, asBlob(dhPart2.pvi), dhResult);
		m_keyExchange.release();
		ZORG_DUMP_VARIABLE(e, "DHResult", dhResult);

		// calculate s0
		std::auto_ptr<Crypto::Hash> s0(m_hashFunction->Create(e));

		if(ZORG_SUCCESS(e))
		{
		    s0->next(e, asBlob(int32_BE(1)));
		    addDHResultToHash(e, s0.get(), dhResult);
		    s0->next(e, asBlob("ZRTP-HMAC-KDF"));
		    s0->next(e, asBlob(m_session->m_peerZid));
		    s0->next(e, asBlob(m_session->m_zid));
		    s0->next(e, m_totalHashValue);
		    s0->next(e, asBlob(int32_BE(m_session->m_s1.dataSize)));
		    s0->next(e, m_session->m_s1);
		    s0->next(e, asBlob(int32_BE(0))); // TBD: s2
		    s0->next(e, asBlob(int32_BE(0))); // TBD: s3
		    s0->finish(e, m_s0);
		    s0.release();

		    ZORG_DUMP_VARIABLE(e, "s0", m_s0);
		}

		// calculate srtpkeyi, srtpsalti, srtpkeyr and srtpsaltr, and create SRTP streams
		BitBlob<MAX_CIPHER_KEY_BITS> srtpkeyi;
		KDF(e, m_hashFunction.get(), m_s0, asBlob("Initiator SRTP master key"), m_kdfContext, m_cipherFunction->getKeyBits(), srtpkeyi);
		ZORG_DUMP_VARIABLE(e, "srtpkeyi", srtpkeyi);

		BitBlob<SRTP_SALT_BITS> srtpsalti;
		fillCopy(e, KDF(e, m_hashFunction.get(), m_s0, asBlob("Initiator SRTP master salt"), m_kdfContext, SRTP_SALT_BITS, asBlob(BitArray<MAX_HASH_BITS>())), srtpsalti);
		ZORG_DUMP_VARIABLE(e, "srtpsalti", srtpsalti);

		BitBlob<MAX_CIPHER_KEY_BITS> srtpkeyr;
		KDF(e, m_hashFunction.get(), m_s0, asBlob("Responder SRTP master key"), m_kdfContext, m_cipherFunction->getKeyBits(), srtpkeyr);
		ZORG_DUMP_VARIABLE(e, "srtpkeyr", srtpkeyr);

		BitBlob<SRTP_SALT_BITS> srtpsaltr;
		fillCopy(e, KDF(e, m_hashFunction.get(), m_s0, asBlob("Responder SRTP master salt"), m_kdfContext, SRTP_SALT_BITS, asBlob(BitArray<MAX_HASH_BITS>())), srtpsaltr);
		ZORG_DUMP_VARIABLE(e, "srtpsaltr", srtpsaltr);

		m_srtpSend.reset(m_instance->m_srtp->Create(e, getRTPProfile(e), getRTCPProfile(e), false, srtpkeyr, srtpsaltr));
		m_srtpRecv.reset(m_instance->m_srtp->Create(e, getRTPProfile(e), getRTCPProfile(e), true, srtpkeyi, srtpsalti));

		// calculate sasvalue
		// TBD: multistream
		m_session->m_sasValue = SASValue(e, SASHash(e, m_hashFunction.get(), m_s0, m_kdfContext, asBlob(BitArray<MAX_HASH_BITS>())));
		m_session->m_sasType = m_activeProfile.sasType;
		m_session->m_sasAvailable = ZORG_SUCCESS(e);

	    Confirm1 confirm1;

	    m_instance->generateRandom(e, asBlob(confirm1.cfbIV));
	    confirm1.h0 = m_session->m_h0;
	    confirm1.pbxEnrollment = false; // TBD
	    confirm1.sasVerified = m_session->sasVerifiedInternal();
	    confirm1.allowClear = false; // TBD
	    confirm1.disclosure = m_session->m_profile.disclose;
	    confirm1.cacheExpirationInterval = m_session->m_profile.expireTime; 

	    BitBlob<MAX_HASH_BITS> mackeyr;
	    KDF(e, m_hashFunction.get(), m_s0, asBlob("Responder HMAC key"), m_kdfContext, m_hashFunction->getHashBits(), mackeyr);
	    ZORG_DUMP_VARIABLE(e, "mackeyr", mackeyr);

	    BitBlob<MAX_CIPHER_KEY_BITS> zrtpkeyr;
	    KDF(e, m_hashFunction.get(), m_s0, asBlob("Responder ZRTP key"), m_kdfContext, m_cipherFunction->getKeyBits(), zrtpkeyr);
	    ZORG_DUMP_VARIABLE(e, "zrtpkeyr", zrtpkeyr);

	    m_confirm1.setBody(e, formatConfirm1(e, confirm1, m_hashFunction.get(), mackeyr, m_cipherFunction.get(), zrtpkeyr, m_confirm1.body()));

	    sendMessage(e, LOGC, asBlob(m_confirm1), MessageTypeConfirm1);
		newState = StateResponderConfirming;
	    }

	    break;

	default:
	    unhandled = true;
	    break;
	}

	break;

    case StateResponderConfirming:
	switch(message.messageType)
	{
	case MessageTypeDHPart2:
	    sendMessage(e, LOGC, asBlob(m_confirm1), MessageTypeConfirm1);
	    break;

	case MessageTypeConfirm2:
	    {
		BitBlob<MAX_HASH_BITS> mackeyi;
		KDF(e, m_hashFunction.get(), m_s0, asBlob("Initiator HMAC key"), m_kdfContext, m_hashFunction->getHashBits(), mackeyi);
		ZORG_DUMP_VARIABLE(e, "mackeyi", mackeyi);

		BitBlob<MAX_CIPHER_KEY_BITS> zrtpkeyi;
		KDF(e, m_hashFunction.get(), m_s0, asBlob("Initiator ZRTP key"), m_kdfContext, m_cipherFunction->getKeyBits(), zrtpkeyi);
		ZORG_DUMP_VARIABLE(e, "zrtpkeyi", zrtpkeyi);

		Confirm2 confirm2;
		cookConfirm2(e, LOGC, message.messageBody, m_hashFunction.get(), mackeyi, m_cipherFunction.get(), zrtpkeyi, confirm2);

		// verify MAC of peer's DHPart2
		Words<2> actualDHPart2MAC;
		const Words<2>& expectedDHPart2MAC = bodyMAC(m_peerDHPart2.body());

		truncatedCopy(e, m_instance->m_implictHashFunction->mac(e, asBlob(confirm2.h0), bodyWithoutMAC(m_peerDHPart2.body()), asBlob(BitArray<IMPLICIT_MAC_BITS>())), asBlob(actualDHPart2MAC));

		if(ZORG_FAILURE(e))
		    break;

		if(actualDHPart2MAC != expectedDHPart2MAC)
		    notifySecurityEvent(e, LOGC, SecurityEventBadMessageMAC);

		// check that H0 is consistent with H1
		Words<8> actualH1;
		truncatedCopy(e, m_instance->m_implictHashFunction->hash(e, asBlob(confirm2.h0), asBlob(BitArray<IMPLICIT_MAC_BITS>())), asBlob(actualH1));

		if(ZORG_FAILURE(e))
		    break;

		if(actualH1 != m_peerH1)
		{
		    ZORG_SET_ERROR(e, ErrorZRTPWrongHashImage);
		    break;
		}

		m_peerH0 = confirm2.h0;

		if(!confirm2.sasVerified)
		{
		    ZORG_LOG(1,(LOGC, "peer's V flag is false: resetting V flag"));
		    m_session->setSASVerifiedInternal(false);
		}

		m_session->m_cacheExpirationInterval = std::min(m_session->m_profile.expireTime, confirm2.cacheExpirationInterval);

		newState = secureDone(e, LOGC);

		sendACK(e, LOGC, MessageTypeConf2ACK);
	    }

	    break;

	default:
	    unhandled = true;
	    break;
	}

	break;

    case StateInitiatorKeyAgreement1:
	switch(message.messageType)
	{
	case MessageTypeCommit:
	    newState = handleCommit(e, LOGC, rawMessage, message);
	    break;

	case MessageTypeDHPart1:
	    {
		DHPart1 dhPart1;
		cookDHPart1(e, LOGC, message.messageBody, m_activeProfile.keyAgreementType, dhPart1);

		// calculate peer's H2 from peer's H1
		Words<8> interpolatedH2;
		truncatedCopy(e, m_instance->m_implictHashFunction->hash(e, asBlob(dhPart1.h1), asBlob(BitArray<IMPLICIT_MAC_BITS>())), asBlob(interpolatedH2));

		// verify MAC of peer's Hello
		Words<2> actualHelloMAC;
		const Words<2>& expectedHelloMAC = bodyMAC(m_peerHello.body());

		truncatedCopy(e, m_instance->m_implictHashFunction->mac(e, asBlob(interpolatedH2), bodyWithoutMAC(m_peerHello.body()), asBlob(BitArray<IMPLICIT_MAC_BITS>())), asBlob(actualHelloMAC));

		if(ZORG_FAILURE(e))
		    break;

		if(actualHelloMAC != expectedHelloMAC)
		    notifySecurityEvent(e, LOGC, SecurityEventBadMessageMAC);

		// check that H2 is consistent with H3
		Words<8> actualH3;
		truncatedCopy(e, m_instance->m_implictHashFunction->hash(e, asBlob(interpolatedH2), asBlob(BitArray<IMPLICIT_MAC_BITS>())), asBlob(actualH3));

		if(ZORG_FAILURE(e))
		    break;

		if(actualH3 != m_peerH3)
		{
		    ZORG_SET_ERROR(e, ErrorZRTPWrongHashImage);
		    break;
		}

		// check that the pvr is not an insecure value
		checkPV(e, asBlob(dhPart1.pvr), m_activeProfile.keyAgreementType);

		cancelSendMessage(e);

		if(ZORG_FAILURE(e))
		    break;

		m_peerDHPart1.copyBody(message.messageBody);
		m_peerH1 = dhPart1.h1;
		m_peerH2 = interpolatedH2;

		// key exchange
		BitBlob<MAX_PV_BITS> dhResult;

		m_keyExchange->agree(e, dhPart1.pvr, dhResult);
		m_keyExchange.release();
		ZORG_DUMP_VARIABLE(e, "DHResult", dhResult);

		// finish calculating total_hash
		m_totalHash->next(e, message.messageBody);
		m_totalHash->next(e, m_dhPart2.body());
		m_totalHash->finish(e, m_totalHashValue);
		m_totalHash.release();
		ZORG_DUMP_VARIABLE(e, "total_hash", m_totalHashValue);

		// calculate KDF_Context
		memcpy(m_kdfContext.bytes, m_session->m_zid.bytes, ZID::BYTES);
		memcpy(m_kdfContext.bytes + ZID::BYTES, m_session->m_peerZid.bytes, ZID::BYTES);
		memcpy(m_kdfContext.bytes + ZID::BYTES + ZID::BYTES, m_totalHashValue.buffer, m_totalHashValue.dataSize);
		m_kdfContext.dataSize = ZID::BYTES + ZID::BYTES + m_totalHashValue.dataSize;
		ZORG_DUMP_VARIABLE(e, "KDF_Context", m_kdfContext);

		// calculate s1
		ZORG_DUMP_VARIABLE(e, "rs1IDr", dhPart1.rs1IDr);
		ZORG_DUMP_VARIABLE(e, "rs2IDr", dhPart1.rs2IDr);

		bool continuityLost = false;
		calculateS1(e, m_session->m_rs1, m_session->m_rs2, m_session->m_peerRS1ID, m_session->m_peerRS2ID, dhPart1.rs1IDr, dhPart1.rs2IDr, m_session->m_s1, continuityLost);
		ZORG_DUMP_VARIABLE(e, "s1", m_session->m_s1);

		// loss of continuity with the previous session: we can no longer trust the previous value of the SAS verified flag
		if(ZORG_SUCCESS(e) && continuityLost)
		{
		    ZORG_LOG(1,(LOGC, "previous session lost: resetting V flag"));
		    m_session->setSASVerifiedInternal(false);
		}

		// calculate s0
		std::auto_ptr<Crypto::Hash> s0(m_hashFunction->Create(e));

		if(ZORG_SUCCESS(e))
		{
		    s0->next(e, asBlob(int32_BE(1)));
		    addDHResultToHash(e, s0.get(), dhResult);
		    s0->next(e, asBlob("ZRTP-HMAC-KDF"));
		    s0->next(e, asBlob(m_session->m_zid));
		    s0->next(e, asBlob(m_session->m_peerZid));
		    s0->next(e, m_totalHashValue);
		    s0->next(e, asBlob(int32_BE(m_session->m_s1.dataSize)));
		    s0->next(e, m_session->m_s1);
		    s0->next(e, asBlob(int32_BE(0))); // TBD: s2
		    s0->next(e, asBlob(int32_BE(0))); // TBD: s3
		    s0->finish(e, m_s0);
		    s0.release();

		    ZORG_DUMP_VARIABLE(e, "s0", m_s0);
		}

		// calculate srtpkeyi, srtpsalti, srtpkeyr and srtpsaltr, and create SRTP streams
		BitBlob<MAX_CIPHER_KEY_BITS> srtpkeyi;
		KDF(e, m_hashFunction.get(), m_s0, asBlob("Initiator SRTP master key"), m_kdfContext, m_cipherFunction->getKeyBits(), srtpkeyi);
		ZORG_DUMP_VARIABLE(e, "srtpkeyi", srtpkeyi);

		BitBlob<SRTP_SALT_BITS> srtpsalti;
		fillCopy(e, KDF(e, m_hashFunction.get(), m_s0, asBlob("Initiator SRTP master salt"), m_kdfContext, SRTP_SALT_BITS, asBlob(BitArray<MAX_HASH_BITS>())), srtpsalti);
		ZORG_DUMP_VARIABLE(e, "srtpsalti", srtpsalti);

		BitBlob<MAX_CIPHER_KEY_BITS> srtpkeyr;
		KDF(e, m_hashFunction.get(), m_s0, asBlob("Responder SRTP master key"), m_kdfContext, m_cipherFunction->getKeyBits(), srtpkeyr);
		ZORG_DUMP_VARIABLE(e, "srtpkeyr", srtpkeyr);

		BitBlob<SRTP_SALT_BITS> srtpsaltr;
		fillCopy(e, KDF(e, m_hashFunction.get(), m_s0, asBlob("Responder SRTP master salt"), m_kdfContext, SRTP_SALT_BITS, asBlob(BitArray<MAX_HASH_BITS>())), srtpsaltr);
		ZORG_DUMP_VARIABLE(e, "srtpsaltr", srtpsaltr);

		m_srtpSend.reset(m_instance->m_srtp->Create(e, getRTPProfile(e), getRTCPProfile(e), false, srtpkeyi, srtpsalti));
		m_srtpRecv.reset(m_instance->m_srtp->Create(e, getRTPProfile(e), getRTCPProfile(e), true, srtpkeyr, srtpsaltr));

		// calculate sasvalue
		// TBD: multistream
		m_session->m_sasValue = SASValue(e, SASHash(e, m_hashFunction.get(), m_s0, m_kdfContext, asBlob(BitArray<MAX_HASH_BITS>())));
		m_session->m_sasType = m_activeProfile.sasType;
		m_session->m_sasAvailable = ZORG_SUCCESS(e);

		sendMessage(e, LOGC, asBlob(m_dhPart2), MessageTypeDHPart2, m_instance->m_t2MaxRetransmit, m_instance->m_t2, m_instance->m_t2Cap);

		newState = StateInitiatorKeyAgreement2;
	    }

	    break;

	default:
	    unhandled = true;
	    break;
	}

	break;

    case StateInitiatorKeyAgreement2:
	switch(message.messageType)
	{
	case MessageTypeConfirm1:
	    {
		BitBlob<MAX_HASH_BITS> mackeyr;
		KDF(e, m_hashFunction.get(), m_s0, asBlob("Responder HMAC key"), m_kdfContext, m_hashFunction->getHashBits(), mackeyr);
		ZORG_DUMP_VARIABLE(e, "mackeyr", mackeyr);

		BitBlob<MAX_CIPHER_KEY_BITS> zrtpkeyr;
		KDF(e, m_hashFunction.get(), m_s0, asBlob("Responder ZRTP key"), m_kdfContext, m_cipherFunction->getKeyBits(), zrtpkeyr);
		ZORG_DUMP_VARIABLE(e, "zrtpkeyr", zrtpkeyr);

		Confirm1 confirm1;
		cookConfirm1(e, LOGC, message.messageBody, m_hashFunction.get(), mackeyr, m_cipherFunction.get(), zrtpkeyr, confirm1);

		// verify MAC of peer's DHPart1
		Words<2> actualDHPart1MAC;
		const Words<2>& expectedDHPart1MAC = bodyMAC(m_peerDHPart1.body());

		truncatedCopy(e, m_instance->m_implictHashFunction->mac(e, asBlob(confirm1.h0), bodyWithoutMAC(m_peerDHPart1.body()), asBlob(BitArray<IMPLICIT_MAC_BITS>())), asBlob(actualDHPart1MAC));

		if(ZORG_FAILURE(e))
		    break;

		if(actualDHPart1MAC != expectedDHPart1MAC)
		    notifySecurityEvent(e, LOGC, SecurityEventBadMessageMAC);

		// check that H0 is consistent with H1
		Words<8> actualH1;
		truncatedCopy(e, m_instance->m_implictHashFunction->hash(e, asBlob(confirm1.h0), asBlob(BitArray<IMPLICIT_MAC_BITS>())), asBlob(actualH1));

		if(ZORG_FAILURE(e))
		    break;

		if(actualH1 != m_peerH1)
		{
		    ZORG_SET_ERROR(e, ErrorZRTPWrongHashImage);
		    break;
		}

		m_peerH0 = confirm1.h0;

		// cancel retransmission of DHPart2
		cancelSendMessage(e);

		if(!confirm1.sasVerified)
		{
		    ZORG_LOG(1,(LOGC, "peer's V flag is false: resetting V flag"));
    		    m_session->setSASVerifiedInternal(false);
		}

		m_session->m_cacheExpirationInterval = std::min(m_session->m_profile.expireTime, confirm1.cacheExpirationInterval);

		Confirm2 confirm2;
		confirm2.h0 = m_session->m_h0;
		confirm2.pbxEnrollment = false; // TBD
		confirm2.sasVerified = m_session->sasVerifiedInternal();
		confirm2.allowClear = false; // TBD
		confirm2.disclosure = m_session->m_profile.disclose;
		confirm2.cacheExpirationInterval = m_session->m_profile.expireTime;

		BitBlob<MAX_HASH_BITS> mackeyi;
		KDF(e, m_hashFunction.get(), m_s0, asBlob("Initiator HMAC key"), m_kdfContext, m_hashFunction->getHashBits(), mackeyi);
		ZORG_DUMP_VARIABLE(e, "mackeyi", mackeyi);

		BitBlob<MAX_CIPHER_KEY_BITS> zrtpkeyi;
		KDF(e, m_hashFunction.get(), m_s0, asBlob("Initiator ZRTP key"), m_kdfContext, m_cipherFunction->getKeyBits(), zrtpkeyi);
		ZORG_DUMP_VARIABLE(e, "zrtpkeyi", zrtpkeyi);

		m_confirm2.setBody(e, formatConfirm2(e, confirm2, m_hashFunction.get(), mackeyi, m_cipherFunction.get(), zrtpkeyi, m_confirm2.body()));
		sendMessage(e, LOGC, asBlob(m_confirm2), MessageTypeConfirm2, m_instance->m_t2MaxRetransmit, m_instance->m_t2, m_instance->m_t2Cap);

		newState = StateInitiatorConfirming;
	    }

	    break;

	default:
	    unhandled = true;
	    break;
	}

	break;

    case StateInitiatorConfirming:
	switch(message.messageType)
	{
	case MessageTypeNone:
	    m_srtpRecv->unprotectRTP_InPlace(e, rawMessage);

	    if(ZORG_SUCCESS(e))
	    {
		cancelSendMessage(e);
		newState = secureDone(e, LOGC);
	    }

	    unhandled = true;
	    break;

	case MessageTypeConf2ACK:
	    cancelSendMessage(e);
	    newState = secureDone(e, LOGC);
	    break;

	default:
	    unhandled = true;
	    break;
	}

	break;

    default:
	ZORG_UNREACHABLE();
	break;
    }

l_Epilog:
    if(newState != StateUnknown)
	setState(e, LOGC, newState);

    if(ZORG_ERROR_CODE(e) == ErrorInternalAbort)
    {
	ZORG_CLEAR_ERROR(e);
	return NullBlob;
    }

    if(ZORG_FAILURE(e))
    {
	ZORG_DECL_ERROR(e2);
	halt(e2, e);
	return NullBlob;
    }

    if(unhandled && message.messageType == MessageTypeNone)
    {
	switch(m_state)
	{
	case StateInitiatorConfirming:
	    // already decrypted by the StateInitiatorConfirming handler
	    return rawMessage;

	case StateSecure:
	    return m_srtpRecv->unprotectRTP_InPlace(e, rawMessage);

	default:
	    if(isFinalState(m_state))
	    {
	case StateDiscovery:
	case StateDiscoveryWaitHello:
	case StateDiscoveryWaitHelloACK:
		ZORG_LOG(3,(LOGC, "bypassing ZRTP in state %s", getStateName(m_state)));
		return rawMessage;
	    }

	    break;
	}
    }

    // when in doubt, drop
    return NullBlob;
}

void Stream::addDHResultToHash(::ZORG::Error& e, Crypto::Hash * hash, const Blob& dhResult)
{
    if(ZORG_FAILURE(e))
	return;

    // for compatibility with a LibZRTP bug: zero-extend DHresult to the size of the corresponding pv
    if(true/*TODO*/)
    {
	size_t pvSize = getPVSize(e, m_activeProfile.keyAgreementType);
	size_t dhResultSize = getDHResultSize(e, m_activeProfile.keyAgreementType);

	if(ZORG_FAILURE(e))
	    return;

	assert(pvSize >= dhResultSize);

	for(size_t i = 0, n = pvSize - dhResultSize; i < n; ++ i)
	    hash->next(e, asBlob(byte(0)));
    }

    hash->next(e, dhResult);
}

Session::Session(::ZORG::Error& e, Instance * instance, SessionInterface * iface, Cache * cache, const ZID& zid, const Profile& profile, bool isInitiator):
    m_instance(instance),
    m_iface(iface),
    m_cache(cache),
    m_zid(zid),
    m_profile(Profile::normalize(profile)),
    m_isInitiator(isInitiator),
    m_peerZidAvailable(false),
    m_sasAvailable(false)
{
    if(ZORG_FAILURE(e))
	return;

    static unsigned sessionId = 0;
    zorg_snprintf(LOGC, sizeof(LOGC) - 1, "zsess%u", ++ sessionId);
    LOGC[sizeof(LOGC) - 1] = 0;

    m_profile.check(e);

    if(ZORG_FAILURE(e))
	return;

    // compute hash chain
    m_instance->generateRandom(e, asBlob(m_h0));
    truncatedCopy(e, m_instance->m_implictHashFunction->hash(e, asBlob(m_h0), asBlob(BitArray<MAX_HASH_BITS>())), asBlob(m_h1));
    truncatedCopy(e, m_instance->m_implictHashFunction->hash(e, asBlob(m_h1), asBlob(BitArray<MAX_HASH_BITS>())), asBlob(m_h2));
    truncatedCopy(e, m_instance->m_implictHashFunction->hash(e, asBlob(m_h2), asBlob(BitArray<MAX_HASH_BITS>())), asBlob(m_h3));

    m_instance->m_sessions.push_back(m_sessionsEntry);

    ZORG_LOG(1,(LOGC, "created on instance %s", m_instance->LOGC));
    ZORG_LOG(1,(LOGC, "zid is %s", ZORG_HEX_LINE_DUMP(m_zid)));
}

Session::~Session()
{
    ZORG_LOG(1,(LOGC, "removed from instance %s", m_instance->LOGC));

    m_sessionsEntry.remove();

    while(!m_streams.empty())
    {
	List& nextStream = m_streams.front();
	m_streams.pop_front();

	// FIXME: this is ugly
	delete reinterpret_cast<Stream *>(reinterpret_cast<char *>(&nextStream) - offsetof(Stream, m_streamsEntry)); 
    }

    m_iface->cancelAllTasks();

    ZORG_LOG(1,(LOGC, "destroyed"));
}

const ::ZORG::ZRTP::Instance * Session::instance() { return m_instance; }
const ZID& Session::zid() { return m_zid; }

const ZID& Session::peerZID(::ZORG::Error& e)
{
    if(ZORG_SUCCESS(e) && !m_peerZidAvailable)
	ZORG_SET_ERROR(e, ErrorZRTPUnavailable);

    return m_peerZid;
}

const Crypto::SASValue& Session::sasValue(::ZORG::Error& e)
{
    if(ZORG_SUCCESS(e) && !m_sasAvailable)
	ZORG_SET_ERROR(e, ErrorZRTPUnavailable);

    return m_sasValue;
}

bool Session::sasVerifiedInternal()
{
    ZORG_DECL_ERROR(nonFatal);
    return sasVerified(nonFatal);
}

bool Session::sasVerified(::ZORG::Error& e)
{
    if(ZORG_FAILURE(e))
	return false;

    if(!m_peerZidAvailable)
    {
	ZORG_SET_ERROR(e, ErrorZRTPUnavailable);
	return false;
    }

    bool ret = false;

    if(m_cache == NULL)
	return false;

    if(!m_cache->getVerified(m_zid, m_peerZid, ret))
    {
	ZORG_SET_ERROR(e, ErrorZRTPSecretNotFound);
	return false;
    }

    return ret;
}

void Session::setSASVerifiedInternal(bool isVerified)
{
    ZORG_DECL_ERROR(nonFatal);
    this->setSASVerified(nonFatal, isVerified);
}

void Session::updateCache()
{
    if(/*!m_cacheMismatch && *//*FIXME*/m_cache)
    {
	assert(m_peerZidAvailable);
	assert(m_rs1.dataSize);
	ZORG_LOG(3,(LOGC, "updating cache: <%s:%s> = %s", ZORG_HEX_LINE_DUMP(m_zid), ZORG_HEX_LINE_DUMP(m_peerZid), ZORG_HEX_LINE_DUMP(m_rs1)));
	m_cache->updateEntry(m_zid, m_peerZid, m_rs1, m_cacheExpirationInterval); // FIXME: expiration is relative to when Confirm1 is sent/received
    }
}

void Session::lookupCache()
{
    if(m_cache)
    {
	assert(m_peerZidAvailable);
	m_cache->lookupEntry(m_zid, m_peerZid, m_rs1, m_rs2);
    }
    else
    {
	m_rs1.dataSize = 0;
	m_rs2.dataSize = 0;
    }

    ZORG_DECL_ERROR(e);
    ZORG_DUMP_VARIABLE(e, "rs1", m_rs1);
    ZORG_DUMP_VARIABLE(e, "rs2", m_rs2);
}

void Session::setSASVerified(::ZORG::Error& e, bool isVerified)
{
    if(ZORG_FAILURE(e))
	return;

    if(!m_peerZidAvailable)
    {
	ZORG_SET_ERROR(e, ErrorZRTPUnavailable);
	return;
    }

    // TODO? set locally?
    if(m_cache == NULL)
	return;

    // FIXME
 //   if(isVerified && m_cacheMismatch)
 //   {
	//m_cacheMismatch = false;
	//updateCache();
 //   }

    if(!m_cache->setVerified(m_zid, m_peerZid, isVerified))
    {
	ZORG_SET_ERROR(e, ErrorZRTPSecretNotFound);
	return;
    }
}

const Crypto::SAS& Session::sas(::ZORG::Error& e, Crypto::SAS& sas)
{
    if(ZORG_FAILURE(e))
	return sas;

    if(!m_sasAvailable)
    {
	ZORG_SET_ERROR(e, ErrorZRTPUnavailable);
	return sas;
    }

    std::auto_ptr<Crypto::SASFunction> sasFunction(m_instance->m_cryptoSuite->createSASFunction(e, m_sasType));

    if(ZORG_SUCCESS(e))
	sas = sasFunction->render(e, m_sasValue, sas);

    return sas;
}

::ZORG::ZRTP::Stream * Session::createStream(::ZORG::Error& e, StreamInterface * iface)
{
    return guard_new(e, new(e) Stream(e, m_instance, this, iface, m_isInitiator));
}

Instance::Instance(::ZORG::Error& e, CryptoSuite * cryptoSuite, SRTP::SRTPInstance * srtpImpl):
    m_cryptoSuite(cryptoSuite),
    m_srtp(srtpImpl)
{
    if(ZORG_FAILURE(e))
	return;

    assert(cryptoSuite && srtpImpl);

    if(cryptoSuite == NULL || srtpImpl == NULL)
    {
	ZORG_SET_ERROR(e, ErrorArgument);
	return;
    }

    static unsigned instanceId = 0;
    zorg_snprintf(LOGC, sizeof(LOGC) - 1, "z.org%u", ++ instanceId);
    LOGC[sizeof(LOGC) - 1] = 0;

    m_cryptoSuite->selfTest(e);

    if(ZORG_FAILURE(e))
    {
	ZORG_LOG(1,(LOGC, "crypto suite failed self-test"));
	return;
    }

    m_implictHashFunction.reset(m_cryptoSuite->createHashFunction(e, HashS256));
    m_rng.reset(m_cryptoSuite->createRNG(e));

    // TODO: make these configurable
    //m_t1 = 50;
    //m_t1Cap = 200;
    //m_t1MaxRetransmit = 20;
    m_t1 = 50;
    m_t1Cap = 200;
    m_t1MaxRetransmit = 200;
    m_t2 = 150;
    m_t2Cap = 1200;
    m_t2MaxRetransmit = 10;
    //m_t2 = 50;
    //m_t2Cap = 50;
    //m_t2MaxRetransmit = 400;

    if(ZORG_FAILURE(e))
	return;

    ZORG_LOG(1,(LOGC, "created"));
}

Instance::~Instance()
{
    while(!m_sessions.empty())
    {
	List& nextSession = m_sessions.front();
	m_sessions.pop_front();

	// FIXME: this is ugly
	delete reinterpret_cast<Session *>(reinterpret_cast<char *>(&nextSession) - offsetof(Session, m_sessionsEntry)); 
    }

    ZORG_LOG(1,(LOGC, "destroyed"));
}

::ZORG::ZRTP::Instance * Instance::Create(::ZORG::Error& e, CryptoSuite * cryptoSuite, SRTP::SRTPInstance * srtpImpl)
{
    return guard_new(e, new(e) Instance(e, cryptoSuite, srtpImpl));
}

Session * Instance::createSession(::ZORG::Error& e, SessionInterface * iface, Cache * cache, const ZID& zid, const Profile& profile, bool isInitiator)
{
    return guard_new(e, new(e) Session(e, this, iface, cache, zid, profile, isInitiator));
}

void Instance::addEntropy(::ZORG::Error& e, const Blob& seed)
{
    return m_rng->addEntropy(e, seed);
}

const Blob& Instance::generateRandom(::ZORG::Error& e, size_t nbyte, Blob& randbuf)
{
    return m_rng->generateRandom(e, nbyte, randbuf);
}

}

Profile Profile::Default()
{
    Profile profile = Profile();

    profile.autoSecure = true;
    profile.disclose = false;
    profile.fastAcknowledge = true;
    profile.hashAlgorithmsImplyMandatory = true;
    profile.cipherAlgorithmsImplyMandatory = true;
    profile.authTagTypesImplyMandatory = true;
    profile.keyAgreementTypesImplyMandatory = true;
    profile.sasTypesImplyMandatory = true;
    profile.expireTime = 0xffffffff;
    profile.clientId[0] = 0;

    return profile;
}

bool Profile::check(::ZORG::Error& e) const
{
    if(ZORG_FAILURE(e))
	return false;

    // TODO
    return true;
}

const Profile& Profile::normalize(Profile& profile)
{
    if(profile.hashAlgorithmsImplyMandatory)
	profile.hashAlgorithms += MANDATORY_HASH_ALGORITHMS;

    if(profile.cipherAlgorithmsImplyMandatory)
	profile.cipherAlgorithms += MANDATORY_CIPHER_ALGORITHMS;

    if(profile.authTagTypesImplyMandatory)
	profile.authTagTypes += MANDATORY_AUTH_TAG_TYPES;

    if(profile.keyAgreementTypesImplyMandatory)
	profile.keyAgreementTypes += MANDATORY_KEY_AGREEMENT_TYPES;

    if(profile.sasTypesImplyMandatory)
	profile.sasTypes += MANDATORY_SAS_TYPES;

    return profile;
}

Instance * Instance::Create(::ZORG::Error& e, CryptoSuite * cryptoSuite, SRTP::SRTPInstance * srtpImpl)
{
    return Internal::Instance::Create(e, cryptoSuite, srtpImpl);
}

}
}

// EOF
