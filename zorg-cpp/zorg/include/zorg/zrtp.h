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

#ifndef ZORG_ZRTP_H_
#define ZORG_ZRTP_H_

#include <zorg/zorg.h>
#include <zorg/srtp.h>
#include <zorg/crypto.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct Zorg_ZID
{
    unsigned char data[12];
};

enum Zorg_HashAlgorithm
{
    Zorg_HashUnknown,
    Zorg_HashS256,
    Zorg_HashS384,
    Zorg_HashN256,
    Zorg_HashN384,
    Zorg_Hash_Top,
    Zorg_Hash_Count = Zorg_Hash_Top - 1
};

enum Zorg_CipherAlgorithm
{
    Zorg_CipherUnknown,
    Zorg_CipherAES1,
    Zorg_CipherAES2,
    Zorg_CipherAES3,
    Zorg_Cipher2FS1,
    Zorg_Cipher2FS2,
    Zorg_Cipher2FS3,
    Zorg_CipherCAM1,
    Zorg_CipherCAM2,
    Zorg_CipherCAM3,
    Zorg_Cipher_Top,
    Zorg_Cipher_Count = Zorg_Cipher_Top - 1
};

enum Zorg_AuthTagType
{
    Zorg_AuthTagUnknown,
    Zorg_AuthTagHS32,
    Zorg_AuthTagHS80,
    Zorg_AuthTagSK32,
    Zorg_AuthTagSK64,
    Zorg_AuthTag_Top,
    Zorg_AuthTag_Count = Zorg_AuthTag_Top - 1
};

enum Zorg_KeyAgreementType
{
    Zorg_KeyAgreementUnknown,
    Zorg_KeyAgreementDH3k,
    Zorg_KeyAgreementDH2k,
    Zorg_KeyAgreementEC25,
    Zorg_KeyAgreementEC38,
    Zorg_KeyAgreementEC52,
    Zorg_KeyAgreementPrsh,
    Zorg_KeyAgreementMult,
    Zorg_KeyAgreement_Top,
    Zorg_KeyAgreement_Count = Zorg_KeyAgreement_Top - 1
};

enum Zorg_SASType
{
    Zorg_SASUnknown,
    Zorg_SASB32,
    Zorg_SASB256,
    Zorg_SAS_Top,
    Zorg_SAS_Count = Zorg_SAS_Top - 1
};

enum Zorg_ProfileConstants
{
    Zorg_Profile_ComponentsMaxCount = 7
};

struct Zorg_Profile
{
    int autoSecure;
    int disclose;
    int fastAcknowledge;
    int hashAlgorithmsImplyMandatory;
    int cipherAlgorithmsImplyMandatory;
    int authTagTypesImplyMandatory;
    int keyAgreementTypesImplyMandatory;
    int sasTypesImplyMandatory;
    enum Zorg_HashAlgorithm hashAlgorithms[Zorg_Profile_ComponentsMaxCount];
    enum Zorg_CipherAlgorithm cipherAlgorithms[Zorg_Profile_ComponentsMaxCount];
    enum Zorg_AuthTagType authTagTypes[Zorg_Profile_ComponentsMaxCount];
    enum Zorg_KeyAgreementType keyAgreementTypes[Zorg_Profile_ComponentsMaxCount];
    enum Zorg_SASType sasTypes[Zorg_Profile_ComponentsMaxCount];
    unsigned long expireTime;
    char clientId[16 + 1];
};

int Zorg_Profile_Check(Zorg_Error * e, const struct Zorg_Profile * profile);
void Zorg_Profile_Default(struct Zorg_Profile * profile);

struct Zorg_ActiveProfile
{
    enum Zorg_HashAlgorithm hashAlgorithm;
    enum Zorg_CipherAlgorithm cipherAlgorithm;
    enum Zorg_AuthTagType authTagType;
    enum Zorg_KeyAgreementType keyAgreementType;
    enum Zorg_SASType sasType;
};

enum Zorg_Event
{
    Zorg_EventStop,
    Zorg_EventNoZRTP,
    Zorg_EventClear,
    Zorg_EventSecure,
    Zorg_EventDiscovery,
    Zorg_EventKeyAgreement,
    Zorg_EventConfirming,
    Zorg_EventLocalError
};

enum Zorg_SecurityEvent
{
    Zorg_SecurityEventError,
    Zorg_SecurityEventCacheMismatch,
    Zorg_SecurityEventBadHelloHash,
    Zorg_SecurityEventBadMessageMAC
};

struct Zorg;
struct Zorg_Session;
struct Zorg_Stream;
struct Zorg_Task;
struct Zorg_TaskCookie;
struct Zorg_CryptoSuite;
struct Zorg_Cache;

typedef struct Zorg_CryptoSuite Zorg_CryptoSuite;
typedef struct Zorg_Cache Zorg_Cache;
typedef struct Zorg Zorg;
typedef struct Zorg_Session Zorg_Session;
typedef struct Zorg_Stream Zorg_Stream;
typedef struct Zorg_Task Zorg_Task;
typedef struct Zorg_TaskCookie Zorg_TaskCookie;

typedef struct Zorg_SessionInterface
{
    Zorg_TaskCookie * (* runTask)(Zorg_Error * e, Zorg_Session * session, Zorg_Task * task, int delay);
    void (* cancelTask)(Zorg_Error * e, Zorg_Session * session, Zorg_TaskCookie * taskId);
    void (* cancelAllTasks)(Zorg_Session * session);
}
Zorg_SessionInterface;

typedef struct Zorg_StreamInterface
{
    void (* sendMessage)(Zorg_Error * e, Zorg_Stream * stream, const struct Zorg_Blob * messagePacket);
    void (* onProtocolEvent)(Zorg_Stream * stream, enum Zorg_Event evt);
    void (* onSecurityEvent)(Zorg_Stream * stream, enum Zorg_SecurityEvent evt);
}
Zorg_StreamInterface;

Zorg * Zorg_Create(struct Zorg_Error * e, Zorg_CryptoSuite * cryptoSuite, Zorg_SRTP * srtpImpl, void * userData);
void Zorg_Destroy(Zorg * zorg);
void Zorg_SetUserData(Zorg * zorg, void * userData);
void * Zorg_GetUserData(Zorg * zorg);
void Zorg_AddEntropy(struct Zorg_Error * e, Zorg * zorg, const struct Zorg_Blob * seed);
const struct Zorg_Blob * Zorg_GenerateRandom(struct Zorg_Error * e, Zorg * zorg, size_t nbyte, struct Zorg_Blob * randbuf);

Zorg_Session * Zorg_CreateSession(struct Zorg_Error * e, Zorg * zorg, const Zorg_SessionInterface * iface, Zorg_Cache * cache, const struct Zorg_ZID * zid, const struct Zorg_Profile * profile, int isInitiator, void * userData);
void Zorg_Session_Destroy(Zorg_Session * session);
void Zorg_Session_SetUserData(Zorg_Session * session, void * userData);
void * Zorg_Session_GetUserData(Zorg_Session * session);
Zorg * Zorg_Session_GetZorg(Zorg_Session * session);
struct Zorg_ZID Zorg_Session_GetZID(Zorg_Session * session);
struct Zorg_ZID Zorg_Session_GetPeerZID(struct Zorg_Error * e, Zorg_Session * session);
struct Zorg_SASValue Zorg_Session_GetSASValue(struct Zorg_Error * e, Zorg_Session * session);
const struct Zorg_SAS * Zorg_Session_GetSAS(struct Zorg_Error * e, Zorg_Session * session, struct Zorg_SAS * sas);
int Zorg_Session_GetSASVerified(struct Zorg_Error * e, Zorg_Session * session);
void Zorg_Session_SetSASVerified(struct Zorg_Error * e, Zorg_Session * session, int isVerified);

Zorg_Stream * Zorg_Session_CreateStream(struct Zorg_Error * e, Zorg_Session * session, const Zorg_StreamInterface * iface, void * userData);
void Zorg_Stream_Destroy(Zorg_Stream * stream);
void Zorg_Stream_SetUserData(Zorg_Stream * stream, void * userData);
void * Zorg_Stream_GetUserData(Zorg_Stream * stream);
Zorg_Session * Zorg_Stream_GetSession(Zorg_Stream * stream);
void Zorg_Stream_Start(struct Zorg_Error * e, Zorg_Stream * stream, const struct Zorg_SSRC * ssrc);
void Zorg_Stream_Stop(Zorg_Stream * stream);
void Zorg_Stream_Halt(struct Zorg_Error * e, Zorg_Stream * stream, const struct Zorg_Error * stopError);
const struct Zorg_Blob * Zorg_Stream_GetSDPZrtpHash(struct Zorg_Error * e, Zorg_Stream * stream, struct Zorg_Blob * helloHash);
void Zorg_Stream_SetPeerSDPZrtpHash(struct Zorg_Error * e, Zorg_Stream * stream, const struct Zorg_Blob * peerHelloHash);
const struct Zorg_Blob * Zorg_Stream_ProtectRTP_InPlace(struct Zorg_Error * e, Zorg_Stream * stream, struct Zorg_Blob * rtpPacket);
const struct Zorg_Blob * Zorg_Stream_ProtectRTCP_InPlace(struct Zorg_Error * e, Zorg_Stream * stream, struct Zorg_Blob * rtcpPacket);
const struct Zorg_Blob * Zorg_Stream_UnprotectSRTP_InPlace(struct Zorg_Error * e, Zorg_Stream * stream, struct Zorg_Blob * srtpPacket);
const struct Zorg_Blob * Zorg_Stream_UnprotectSRTCP_InPlace(struct Zorg_Error * e, Zorg_Stream * stream, struct Zorg_Blob * srtcpPacket);

void Zorg_Task_Run(Zorg_Task * task);
void Zorg_Task_Cancel(Zorg_Task * task);

#ifdef __cplusplus
}
#endif

#if defined(__cplusplus) && !defined(ZORG_C_API)

namespace ZORG
{
namespace ZRTP
{

const Blob& KDF(::ZORG::Error& e, Crypto::HashFunction * hashFunction, const Blob& ki, const Blob& label, const Blob& context, uint32_t l, Blob& out);

inline Blob KDF(::ZORG::Error& e, Crypto::HashFunction * hashFunction, const Blob& ki, const Blob& label, const Blob& context, uint32_t l, const Blob& out)
{
    Blob tmp = out;
    return KDF(e, hashFunction, ki, label, context, l, tmp);
}

const Blob& SASHash(::ZORG::Error& e, Crypto::HashFunction * hashFunction, const Blob& s0, const Blob& kdfContext, Blob& sasHash);

inline Blob SASHash(::ZORG::Error& e, Crypto::HashFunction * hashFunction, const Blob& s0, const Blob& kdfContext, const Blob& sasHash)
{
    Blob tmp = sasHash;
    return SASHash(e, hashFunction, s0, kdfContext, tmp);
}

Crypto::SASValue SASValue(::ZORG::Error& e, const Blob& sasHash);

enum Constants
{
    ZID_BITS = 96,
    CLIENT_ID_BYTES = 16,

    RS_BITS = 256,
    PBXSECRET_BITS = 256,
    SRTPS_BITS = 256,
    SASHASH_BITS = 256,
    SRTP_SALT_BITS = 112,
    RS_ID_BITS = 64,
    SRTP_SALT_BYTES = TemplateHell::RoundUpBitsToBytes<SRTP_SALT_BITS>::value,

    WORD_BITS = 32,
    WORD_BYTES = TemplateHell::RoundUpBitsToBytes<WORD_BITS>::value,

    MAX_HASH_BITS = 384,
    MAX_MAC_BITS = MAX_HASH_BITS,

    MAX_CIPHER_BLOCK_BITS = 128,
    MAX_CIPHER_KEY_BITS = 256,
    MAX_CIPHER_CFB_IV_BITS = MAX_CIPHER_BLOCK_BITS,
    MAX_CIPHER_BLOCK_BYTES= TemplateHell::RoundUpBitsToBytes<MAX_CIPHER_BLOCK_BITS>::value,
    MAX_CIPHER_KEY_BYTES = TemplateHell::RoundUpBitsToBytes<MAX_CIPHER_KEY_BITS>::value,
    MAX_CIPHER_CFB_IV_BYTES = TemplateHell::RoundUpBitsToBytes<MAX_CIPHER_CFB_IV_BITS>::value,

    MAX_PV_BITS = 3072,

    MAX_SRTP_KEY_BITS = MAX_CIPHER_KEY_BITS,
    MAX_SRTP_KEY_BYTES = MAX_CIPHER_KEY_BYTES,

    IMPLICIT_HASH_BITS = 256,
    IMPLICIT_MAC_BITS = IMPLICIT_HASH_BITS,
    IMPLICIT_HASH_BYTES = TemplateHell::RoundUpBitsToBytes<IMPLICIT_HASH_BITS>::value,
    IMPLICIT_MAC_BYTES = TemplateHell::RoundUpBitsToBytes<IMPLICIT_MAC_BITS>::value,

    SDP_HASH_HEX_BYTES = IMPLICIT_HASH_BYTES * 2,
    SDP_HASH_ATTRIBUTE_BYTES = (sizeof("1.10 ") - 1) + SDP_HASH_HEX_BYTES
};

struct ZID: public Blnum<ZID_BITS> {};

struct StreamFlags
{
    bool signatureCapable;
    bool mitm;
    bool passive;
};

enum ErrorCode
{
    ErrorUnknown = -1,
    ErrorMalformedPacket = 0x10,
    ErrorCriticalSoftwareError = 0x20,
    ErrorUnsupportedZRTPVersion = 0x30,
    ErrorHelloComponentsMismatch = 0x40,
    ErrorHashTypeNotSupported = 0x51,
    ErrorCipherTypeNotSupported = 0x52,
    ErrorPublicKeyExchangeNotSupported = 0x53,
    ErrorSRTPAuthTagNotSupported = 0x54,
    ErrorSASSchemeNotSupported = 0x55,
    ErrorNoSharedSecret = 0x56,
    ErrorDHBadPV = 0x61,
    ErrorDHHVIMismatch = 0x62,
    ErrorUntrustedMitm = 0x63,
    ErrorBadConfirmMAC = 0x70,
    ErrorNonceReuse = 0x80,
    ErrorZIDCollision = 0x90,
    ErrorSSRCCollision = 0x91,
    ErrorServiceUnavailable = 0xA0,
    ErrorProtocolTimeout = 0xB0,
    ErrorGoClearDisallowed = 0x100
};

inline ::ZORG::ErrorCode asErrorCode(ErrorCode e)
{
    return static_cast</*digraphs suck*/::ZORG::ErrorCode>(static_cast<unsigned>(::ZORG::ErrorZRTPProtocolErrorLow) + static_cast<unsigned>(e));
}

inline bool isProtocolError(const ::ZORG::ErrorCode& e)
{
    return e >= ::ZORG::ErrorZRTPProtocolErrorLow && e <= ::ZORG::ErrorZRTPProtocolErrorHigh;
}

inline ErrorCode toProtocolError(::ZORG::ErrorCode e)
{
    if(isProtocolError(e))
	return static_cast<ErrorCode>(static_cast<unsigned>(e) - static_cast<unsigned>(::ZORG::ErrorZRTPProtocolErrorLow));
    else
	return ErrorCriticalSoftwareError;
}

enum MessageType
{
    MessageTypeUnknown = -1,
    MessageTypeNone,
    MessageTypeHello,
    MessageTypeHelloACK,
    MessageTypeCommit,
    MessageTypeDHPart1,
    MessageTypeDHPart2,
    MessageTypeConfirm1,
    MessageTypeConfirm2,
    MessageTypeConf2ACK,
    MessageTypeError,
    MessageTypeErrorACK,
    MessageTypeGoClear,
    MessageTypeClearACK,
    MessageTypeSASrelay,
    MessageTypeRelayACK,
    MessageTypePing,
    MessageTypePingACK
};

enum ProtocolVersion
{
    ProtocolVersionUnknown = -1,
    ProtocolVersionUnsupported,
    ProtocolVersion1_10
};

typedef ::Zorg_HashAlgorithm HashAlgorithm;

static const HashAlgorithm HashUnknown = ::Zorg_HashUnknown;
static const HashAlgorithm HashS256 = ::Zorg_HashS256;
static const HashAlgorithm HashS384 = ::Zorg_HashS384;
static const HashAlgorithm HashN256 = ::Zorg_HashN256;
static const HashAlgorithm HashN384 = ::Zorg_HashN384;
static const HashAlgorithm HashTop = ::Zorg_Hash_Top;
static const HashAlgorithm HashCount = ::Zorg_Hash_Count;

typedef EnumMask<HashAlgorithm, HashS256, HashN384> HashAlgorithmMask;
typedef EnumList<HashAlgorithm, HashS256, HashN384> HashAlgorithmList;
static HashAlgorithmMask MANDATORY_HASH_ALGORITHMS = HashAlgorithmMask(HashS256);

typedef ::Zorg_CipherAlgorithm CipherAlgorithm;

static const CipherAlgorithm CipherUnknown = ::Zorg_CipherUnknown;
static const CipherAlgorithm CipherAES1 = ::Zorg_CipherAES1;
static const CipherAlgorithm CipherAES2 = ::Zorg_CipherAES2;
static const CipherAlgorithm CipherAES3 = ::Zorg_CipherAES3;
static const CipherAlgorithm Cipher2FS1 = ::Zorg_Cipher2FS1;
static const CipherAlgorithm Cipher2FS2 = ::Zorg_Cipher2FS2;
static const CipherAlgorithm Cipher2FS3 = ::Zorg_Cipher2FS3;
static const CipherAlgorithm CipherCAM1 = ::Zorg_CipherCAM1;
static const CipherAlgorithm CipherCAM2 = ::Zorg_CipherCAM2;
static const CipherAlgorithm CipherCAM3 = ::Zorg_CipherCAM3;
static const CipherAlgorithm CipherTop = ::Zorg_Cipher_Top;
static const CipherAlgorithm CipherCount = ::Zorg_Cipher_Count;

typedef EnumMask<CipherAlgorithm, CipherAES1, CipherCAM3> CipherAlgorithmMask;
typedef EnumList<CipherAlgorithm, CipherAES1, CipherCAM3> CipherAlgorithmList;
static CipherAlgorithmMask MANDATORY_CIPHER_ALGORITHMS = CipherAlgorithmMask(CipherAES1);

typedef ::Zorg_AuthTagType AuthTagType;

static const AuthTagType AuthTagUnknown = ::Zorg_AuthTagUnknown;
static const AuthTagType AuthTagHS32 = ::Zorg_AuthTagHS32;
static const AuthTagType AuthTagHS80 = ::Zorg_AuthTagHS80;
static const AuthTagType AuthTagSK32 = ::Zorg_AuthTagSK32;
static const AuthTagType AuthTagSK64 = ::Zorg_AuthTagSK64;
static const AuthTagType AuthTagTop = ::Zorg_AuthTag_Top;
static const AuthTagType AuthTagCount = ::Zorg_AuthTag_Count;

typedef EnumMask<AuthTagType, AuthTagHS32, AuthTagSK64> AuthTagTypeMask;
typedef EnumList<AuthTagType, AuthTagHS32, AuthTagSK64> AuthTagTypeList;
static AuthTagTypeMask MANDATORY_AUTH_TAG_TYPES = AuthTagTypeMask(AuthTagHS32) + AuthTagTypeMask(AuthTagHS80);

typedef ::Zorg_KeyAgreementType KeyAgreementType;

static const KeyAgreementType KeyAgreementUnknown = ::Zorg_KeyAgreementUnknown;
static const KeyAgreementType KeyAgreementDH3k = ::Zorg_KeyAgreementDH3k;
static const KeyAgreementType KeyAgreementDH2k = ::Zorg_KeyAgreementDH2k;
static const KeyAgreementType KeyAgreementEC25 = ::Zorg_KeyAgreementEC25;
static const KeyAgreementType KeyAgreementEC38 = ::Zorg_KeyAgreementEC38;
static const KeyAgreementType KeyAgreementEC52 = ::Zorg_KeyAgreementEC52;
static const KeyAgreementType KeyAgreementPrsh = ::Zorg_KeyAgreementPrsh;
static const KeyAgreementType KeyAgreementMult = ::Zorg_KeyAgreementMult;
static const KeyAgreementType KeyAgreementTop = ::Zorg_KeyAgreement_Top;
static const KeyAgreementType KeyAgreementCount = ::Zorg_KeyAgreement_Count;

typedef EnumMask<KeyAgreementType, KeyAgreementDH3k, KeyAgreementMult> KeyAgreementTypeMask;
typedef EnumList<KeyAgreementType, KeyAgreementDH3k, KeyAgreementMult> KeyAgreementTypeList;
static KeyAgreementTypeMask MANDATORY_KEY_AGREEMENT_TYPES = KeyAgreementTypeMask(KeyAgreementDH3k);
static KeyAgreementTypeMask MANDATORY_MULTISTREAM_KEY_AGREEMENT_TYPES = KeyAgreementTypeMask(KeyAgreementMult);

typedef ::Zorg_SASType SASType;

static const SASType SASUnknown = ::Zorg_SASUnknown;
static const SASType SASB32 = ::Zorg_SASB32;
static const SASType SASB256 = ::Zorg_SASB256;
static const SASType SASTop = ::Zorg_SAS_Top;
static const SASType SASCount = ::Zorg_SAS_Count;

typedef EnumMask<SASType, SASB32, SASB256> SASTypeMask;
typedef EnumList<SASType, SASB32, SASB256> SASTypeList;
static SASTypeMask MANDATORY_SAS_TYPES = SASTypeMask(SASB32);

template<size_t N> struct Words: public BitArray<N * WORD_BITS> {};
typedef Words<1> Word;

template<size_t N>
const Words<N>& AsWords(const BitArray<N * WORD_BITS>& bits)
{
    return static_cast<const Words<N>&>(bits);
}

template<size_t N, size_t Nbytes>
const Words<N>& AsWords(const char (& bytes)[Nbytes])
{
    return static_cast<const Words<N>&>(asBitArray<N * WORD_BITS>(bytes));
}

template<size_t N, size_t Nbytes>
const Words<N>& AsWords(const unsigned char (& bytes)[Nbytes])
{
    return static_cast<const Words<N>&>(asBitArray<N * WORD_BITS>(bytes));
}

template<size_t N, size_t Nbits>
const Words<N>& AsWords(const BitArray<Nbits>& b)
{
    return static_cast<const Words<N>&>(asBitArray<N * WORD_BITS>(b.bytes));
}

template<size_t Nbytes> const Word& AsWord(const char (& bytes)[Nbytes]) { return AsWords<1>(bytes); }
template<size_t Nbytes> const Word& AsWord(const unsigned char (& bytes)[Nbytes]) { return AsWords<1>(bytes); }
template<size_t Nbits> const Word& AsWord(const BitArray<Nbits>& b) { return AsWords<1>(b.bytes); }

struct CRC: public Word {};

struct Message
{
    MessageType type;
};

struct Hello: public Message
{
    ProtocolVersion version;
    char clientId[CLIENT_ID_BYTES + 1];
    Words<8> h3;
    ZID zid;
    StreamFlags streamFlags;
    HashAlgorithmList hashAlgorithms;
    CipherAlgorithmList cipherAlgorithms;
    AuthTagTypeList authTagTypes;
    KeyAgreementTypeList keyAgreementTypes;
    SASTypeList sasTypes;
    Words<2> mac;
};

struct HelloACK: public Message {};

struct Commit: public Message
{
    Words<8> h2;
    ZID zid;
    HashAlgorithm hashAlgorithm;
    CipherAlgorithm cipherAlgorithm;
    AuthTagType authTagType;
    KeyAgreementType keyAgreementType;
    SASType sasType;

    union KeyAgreementParam
    {
        struct DH
        {
            Words<8> hvi;
        }
        dh;

        struct Multistream
        {
            Words<4> nonce;
        }
        mult;

        struct Preshared
        {
            Words<4> nonce;
            Words<2> keyID;
        }
        prsh;
    }
    kaparam;

    Words<2> mac;
};

struct DHPart1: public Message
{
    Words<8> h1;
    Words<2> rs1IDr;
    Words<2> rs2IDr;
    Words<2> auxsecretIDr;
    Words<2> pbxsecretIDr;
    BitBlob<MAX_PV_BITS> pvr;
    Words<2> mac;
};

struct DHPart2: public Message
{
    Words<8> h1;
    Words<2> rs1IDi;
    Words<2> rs2IDi;
    Words<2> auxsecretIDi;
    Words<2> pbxsecretIDi;
    BitBlob<MAX_PV_BITS> pvi;
    Words<2> mac;
};

struct Confirm: public Message
{
    Words<2> confirmMAC;
    Words<4> cfbIV;
    Words<8> h0;
    bool pbxEnrollment;
    bool sasVerified;
    bool allowClear;
    bool disclosure;
    uint32_t cacheExpirationInterval;
    // TBD: signature
};

typedef Confirm Confirm1, Confirm2;

struct Conf2ACK: public Message { };

struct Error: public Message
{
    ErrorCode errorCode;
};

struct ErrorACK: public Message { };

struct GoClear: public Message { };

struct ClearACK: public Message { };

// TBD: SASrelay

struct RelayACK: public Message { };

struct Ping: public Message
{
    ProtocolVersion version;
    Words<2> endpointHash;
};

struct PingACK: public Message
{
    ProtocolVersion version;
    Words<2> senderEndpointHash;
    Words<2> receivedEndpointHash;
    SSRC receivedSSRC;
};

struct Profile
{
    bool autoSecure;
    bool disclose;
    bool fastAcknowledge;
    bool hashAlgorithmsImplyMandatory;
    bool cipherAlgorithmsImplyMandatory;
    bool authTagTypesImplyMandatory;
    bool keyAgreementTypesImplyMandatory;
    bool sasTypesImplyMandatory;
    HashAlgorithmList hashAlgorithms;
    CipherAlgorithmList cipherAlgorithms;
    AuthTagTypeList authTagTypes;
    KeyAgreementTypeList keyAgreementTypes;
    SASTypeList sasTypes;
    uint32_t expireTime;
    char clientId[16 + 1];

    bool check(::ZORG::Error& e) const;

    static const Profile& normalize(Profile& profile);

    static Profile normalize(const Profile& profile)
    {
	Profile tmp = profile;
	return normalize(tmp);
    }

    static Profile Default();
};

typedef ::Zorg_Event Event;

static const Event EventStop = ::Zorg_EventStop;
static const Event EventNoZRTP = ::Zorg_EventNoZRTP;
static const Event EventClear = ::Zorg_EventClear;
static const Event EventSecure = ::Zorg_EventSecure;
static const Event EventDiscovery = ::Zorg_EventDiscovery;
static const Event EventKeyAgreement = ::Zorg_EventKeyAgreement;
static const Event EventConfirming = ::Zorg_EventConfirming;
static const Event EventLocalError = ::Zorg_EventLocalError;

typedef ::Zorg_SecurityEvent SecurityEvent;

static const SecurityEvent SecurityEventError = ::Zorg_SecurityEventError;
static const SecurityEvent SecurityEventCacheMismatch = ::Zorg_SecurityEventCacheMismatch;
static const SecurityEvent SecurityEventBadHelloHash = ::Zorg_SecurityEventBadHelloHash;
static const SecurityEvent SecurityEventBadMessageMAC = ::Zorg_SecurityEventBadMessageMAC;

typedef ::Zorg_ActiveProfile ActiveProfile;
typedef ::Zorg_CryptoSuite CryptoSuite;
typedef ::Zorg_Cache Cache;
typedef ::Zorg_Task Task;

class Session;
class SessionInterface;

class Stream;
class StreamInterface;

class Instance: public Crypto::RNG
{
public:
    static Instance * Create(::ZORG::Error& e, CryptoSuite * cryptoSuite, SRTP::SRTPInstance * srtpImpl);

    virtual ~Instance() {}
    virtual Session * createSession(::ZORG::Error& e, SessionInterface * iface, Cache * cache, const ZID& zid, const Profile& profile, bool isInitiator = true) = 0;
};

typedef ::Zorg_TaskCookie TaskCookie;

class SessionInterface
{
public:
    virtual TaskCookie * runTask(::ZORG::Error& e, Task * task, int delay) = 0;
    virtual void cancelTask(::ZORG::Error& e, TaskCookie * taskId) = 0;
    virtual void cancelAllTasks() = 0;
};

class Session
{
public:
    virtual ~Session() {}

    virtual const Instance * instance() = 0;
    virtual const ZID& zid() = 0;
    virtual const ZID& peerZID(::ZORG::Error& e) = 0;
    virtual const Crypto::SASValue& sasValue(::ZORG::Error& e) = 0;
    virtual const Crypto::SAS& sas(::ZORG::Error& e, Crypto::SAS& sas) = 0;
    virtual bool sasVerified(::ZORG::Error& e) = 0;
    virtual void setSASVerified(::ZORG::Error& e, bool isVerified) = 0;
    virtual Stream * createStream(::ZORG::Error& e, StreamInterface * iface) = 0;
};

class StreamInterface
{
public:
    virtual void sendMessage(::ZORG::Error& e, Stream * stream, const Blob& messagePacket) = 0;
    virtual void onProtocolEvent(Stream * stream, Event evt) = 0;
    virtual void onSecurityEvent(Stream * stream, SecurityEvent evt) = 0;
};

class Stream
{
public:
    virtual ~Stream() {}

    virtual Session * session() const = 0;
    virtual StreamFlags flags() const = 0;

    virtual void start(::ZORG::Error& e, const SSRC& ssrc) = 0;
    virtual void stop() = 0;
    virtual void halt(::ZORG::Error& e, const ::ZORG::Error& stopError) = 0;

    void halt(::ZORG::Error& e, ::ZORG::ErrorCode errorCode)
    {
	ZORG_DECL_ERROR(stopError);
	ZORG_SET_ERROR(stopError, errorCode);
	this->halt(e, stopError);
    }

    void halt(::ZORG::Error& e, ErrorCode errorCode)
    {
	this->halt(e, asErrorCode(errorCode));
    }

    virtual const Blob& getSDPZrtpHash(::ZORG::Error& e, Blob& a) = 0;
    virtual void setPeerSDPZrtpHash(::ZORG::Error& e, const Blob& a) = 0;

    virtual const Blob& protectRTP_InPlace(::ZORG::Error& e, Blob& rtpPacket) = 0;
    virtual const Blob& protectRTCP_InPlace(::ZORG::Error& e, Blob& rtcpPacket) = 0;
    virtual const Blob& unprotectSRTP_InPlace(::ZORG::Error& e, Blob& srtpPacket) = 0;
    virtual const Blob& unprotectSRTCP_InPlace(::ZORG::Error& e, Blob& srtcpPacket) = 0;
};

}
}

struct Zorg_CryptoSuite
{
public:
    virtual void selfTest(::ZORG::Error& e) = 0;
    virtual ::ZORG::Crypto::RNG * createRNG(::ZORG::Error& e) = 0;
    virtual ::ZORG::Crypto::HashFunction * createHashFunction(::ZORG::Error& e, ::ZORG::ZRTP::HashAlgorithm hashAlgorithm) = 0;
    virtual ::ZORG::Crypto::CipherFunction * createCipherFunction(::ZORG::Error& e, ::ZORG::ZRTP::CipherAlgorithm cipherAlgorithm) = 0;
    virtual ::ZORG::Crypto::KeyExchangeFunction * createKeyAgreementFunction(::ZORG::Error& e, ::ZORG::ZRTP::KeyAgreementType keyAgreementType, ::ZORG::Crypto::RNG * rng) = 0;
    virtual ::ZORG::Crypto::SASFunction * createSASFunction(::ZORG::Error& e, ::ZORG::ZRTP::SASType sasType) = 0;
};

struct Zorg_Cache
{
public:
    virtual void lookupEntry(const ::ZORG::ZRTP::ZID& zid1, const ::ZORG::ZRTP::ZID& zid2, ::ZORG::BitBlob<ZORG::ZRTP::RS_BITS>& rs1, ::ZORG::BitBlob<ZORG::ZRTP::RS_BITS>& rs2) = 0;
    virtual void updateEntry(const ::ZORG::ZRTP::ZID& zid1, const ::ZORG::ZRTP::ZID& zid2, const ::ZORG::BitArray<ZORG::ZRTP::RS_BITS>& rs1, uint32_t ttl) = 0;
    virtual void deleteEntry(const ::ZORG::ZRTP::ZID& zid1, const ::ZORG::ZRTP::ZID& zid2) = 0 ;
    virtual bool getVerified(const ::ZORG::ZRTP::ZID& zid1, const ::ZORG::ZRTP::ZID& zid2, bool& isVerified) = 0;
    virtual bool setVerified(const ::ZORG::ZRTP::ZID& zid1, const ::ZORG::ZRTP::ZID& zid2, bool isVerified) = 0;
    virtual void flush() = 0;
    virtual ~Zorg_Cache() {}
};

struct Zorg_Task
{
public:
    virtual void run() = 0;
    virtual void cancel() = 0;
};

#endif

#endif

// EOF
