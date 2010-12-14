#define NOMINMAX

#include <stdint.h>

#include <zorg/srtp.h>
#include <zorg/crypto.h>

#include <srtp.h>
#include <rtp.h>

using namespace ::ZORG;
using namespace ::ZORG::SRTP;
using namespace ::ZORG::Crypto;
using namespace ::ZORG::Crypto::RFC5764;

class LibSRTPContext: public SRTPContext
{
private:
    srtp_t srtp;

    static srtp_profile_t convertProfile(Error& e, SRTPProfile profile)
    {
	if(ZORG_FAILURE(e))
	    return srtp_profile_reserved;

	switch(profile)
	{
	case SRTP_AES128_CM_HMAC_SHA1_80: return srtp_profile_aes128_cm_sha1_80;
	case SRTP_AES128_CM_HMAC_SHA1_32: return srtp_profile_aes128_cm_sha1_32;
	case SRTP_AES256_CM_HMAC_SHA1_80: return srtp_profile_aes256_cm_sha1_80;
	case SRTP_AES256_CM_HMAC_SHA1_32: return srtp_profile_aes256_cm_sha1_32;
	case SRTP_NULL_HMAC_SHA1_80: return srtp_profile_null_sha1_80;
	case SRTP_NULL_HMAC_SHA1_32: return srtp_profile_null_sha1_32;

	default:
	    ZORG_SET_ERROR(e, ErrorInternal); // TODO: error code
	    return srtp_profile_reserved;
	}
    }

    static void setRTPProfile(Error& e, srtp_policy_t& policy, srtp_profile_t profile)
    {
	if(ZORG_FAILURE(e))
	    return;

	crypto_policy_set_from_profile_for_rtp(&policy.rtp, profile); // TODO: error handling
    }

    static void setRTCPProfile(Error& e, srtp_policy_t& policy, srtp_profile_t profile)
    {
	if(ZORG_FAILURE(e))
	    return;

	crypto_policy_set_from_profile_for_rtcp(&policy.rtcp, profile); // TODO: error handling
    }

public:
    LibSRTPContext(Error& e, SRTPProfile rtpProfile, SRTPProfile rtcpProfile, bool inbound, const Blob& masterKey, const Blob& masterSalt): srtp()
    {
	if(ZORG_FAILURE(e))
	    return;

	srtp_policy_t policy = {};

	srtp_profile_t rtpProfileConverted = convertProfile(e, rtpProfile);
	srtp_profile_t rtcpProfileConverted = convertProfile(e, rtcpProfile);

	// RTP profile
	setRTPProfile(e, policy, rtpProfileConverted);

	// RTCP profile
	setRTCPProfile(e, policy, rtcpProfileConverted);

	if(ZORG_FAILURE(e))
	    return;

	// master key and salt
	unsigned int keyLength = srtp_profile_get_master_key_length(rtpProfileConverted);
	unsigned int saltLength = srtp_profile_get_master_salt_length(rtpProfileConverted);

	if(masterKey.dataSize < keyLength)
	{
	    ZORG_SET_ERROR(e, ErrorKeySize);
	    return;
	}
	
	if(masterSalt.dataSize < saltLength)
	{
	    ZORG_SET_ERROR(e, ErrorSaltSize);
	    return;
	}

	unsigned char key[SRTP_MAX_KEY_LEN];
	assert((keyLength + saltLength) <= sizeof(key));
	
	keyLength = std::min(keyLength, static_cast<unsigned int>(masterKey.dataSize));
	saltLength = std::min(saltLength, static_cast<unsigned int>(masterSalt.dataSize));

	memcpy(key, masterKey.buffer, keyLength);
	append_salt_to_key(key, keyLength, static_cast<unsigned char *>(masterSalt.buffer), saltLength);

	policy.key = key;

	// SSRC
	if(inbound)
	    policy.ssrc.type = ssrc_any_inbound;
	else
	    policy.ssrc.type = ssrc_any_outbound;

	// create session and stream
	srtp_create(&srtp, &policy); // TODO: error handling
	srtp_add_stream(srtp, &policy); // TODO: error handling
    }

    virtual ~LibSRTPContext()
    {
	srtp_dealloc(srtp); // TODO: error handling
    }

    virtual const Blob& protectRTP_InPlace(Error& e, Blob& rtpPacket)
    {
	if(ZORG_FAILURE(e))
	    return NullBlob;

	if(rtpPacket.maxSize < SRTP_MAX_TRAILER_LEN || rtpPacket.maxSize - SRTP_MAX_TRAILER_LEN < rtpPacket.dataSize)
	{
	    ZORG_SET_ERROR(e, ErrorBufferSize);
	    return NullBlob;
	}

	int secure_p_len = rtpPacket.dataSize;
	err_status_t errcheck = srtp_protect(srtp, rtpPacket.buffer, &secure_p_len);

	if(errcheck != err_status_ok)
	{
	    ZORG_SET_ERROR(e, ErrorInternal); // TODO: convert error code
	    return NullBlob;
	}

	assert(secure_p_len <= rtpPacket.maxSize);
	rtpPacket.dataSize = secure_p_len;
        return rtpPacket;
    }

    virtual const Blob& unprotectRTP_InPlace(Error& e, Blob& srtpPacket)
    {
	if(ZORG_FAILURE(e))
	    return NullBlob;

	int plain_p_len = srtpPacket.dataSize;
	err_status_t errcheck = srtp_unprotect(srtp, srtpPacket.buffer, &plain_p_len);

	if(errcheck != err_status_ok)
	{
	    ZORG_SET_ERROR(e, ErrorInternal); // TODO: convert error code
	    return NullBlob;
	}

	assert(plain_p_len <= srtpPacket.dataSize);
	srtpPacket.dataSize = plain_p_len;
        return srtpPacket;
    }

    virtual const Blob& protectRTCP_InPlace(Error& e, Blob& rtcpPacket)
    {
	if(ZORG_FAILURE(e))
	    return NullBlob;

	if(rtcpPacket.maxSize < SRTP_MAX_TRAILER_LEN || rtcpPacket.maxSize - SRTP_MAX_TRAILER_LEN < rtcpPacket.dataSize)
	{
	    ZORG_SET_ERROR(e, ErrorBufferSize);
	    return NullBlob;
	}

	int secure_p_len = rtcpPacket.dataSize;
	err_status_t errcheck = srtp_protect_rtcp(srtp, rtcpPacket.buffer, &secure_p_len);

	if(errcheck != err_status_ok)
	{
	    ZORG_SET_ERROR(e, ErrorInternal); // TODO: convert error code
	    return NullBlob;
	}

	assert(secure_p_len <= rtcpPacket.maxSize);
	rtcpPacket.dataSize = secure_p_len;
	return rtcpPacket;
    }

    virtual const Blob& unprotectRTCP_InPlace(Error& e, Blob& srtcpPacket)
    {
	if(ZORG_FAILURE(e))
	    return NullBlob;

	int plain_p_len = srtcpPacket.dataSize;
	err_status_t errcheck = srtp_unprotect_rtcp(srtp, srtcpPacket.buffer, &plain_p_len);

	if(errcheck != err_status_ok)
	{
	    ZORG_SET_ERROR(e, ErrorInternal); // TODO: convert error code
	    return NullBlob;
	}

	assert(plain_p_len <= srtcpPacket.dataSize);
	srtcpPacket.dataSize = plain_p_len;
        return srtcpPacket;
    }
};

class LibSRTPInstance: public SRTPInstance
{
private:
    static const SRTPProfileMask SUPPORTED_PROFILES;

public:
    virtual SRTPProfileMask SupportedProfiles(const SRTPProfileMask& desired)
    {
	return (SUPPORTED_PROFILES & desired);
    }

    virtual SRTPContext * Create(Error& e, SRTPProfile rtpPolicy, SRTPProfile rtcpPolicy, bool inbound, const Blob& masterKey, const Blob& masterSalt)
    {
	if(ZORG_FAILURE(e))
	    return NULL;

	if(!SUPPORTED_PROFILES[rtpPolicy])
	{
	    ZORG_SET_ERROR(e, ErrorInternal); // TODO: SRTP error codes
	    return NULL;
	}

	if(!SUPPORTED_PROFILES[rtcpPolicy])
	{
	    ZORG_SET_ERROR(e, ErrorInternal); // TODO: SRTP error codes
	    return NULL;
	}

        return guard_new(e, new(e) LibSRTPContext(e, rtpPolicy, rtcpPolicy, inbound, masterKey, masterSalt));
    }
};

const SRTPProfileMask LibSRTPInstance::SUPPORTED_PROFILES = SRTPProfileMask() |
    SRTP_AES128_CM_HMAC_SHA1_80 |
    SRTP_AES128_CM_HMAC_SHA1_32 |
    SRTP_AES256_CM_HMAC_SHA1_80 |
    SRTP_AES256_CM_HMAC_SHA1_32 |
    SRTP_NULL_HMAC_SHA1_80 |
    SRTP_NULL_HMAC_SHA1_32;

namespace ZORG
{
namespace SRTP
{
namespace Libsrtp
{

void Init(Error& e)
{
    if(ZORG_FAILURE(e))
	return;

    srtp_init(); // FIXME: error checking
}

void Deinit()
{
    srtp_deinit(); // FIXME: error checking
}

SRTPInstance * Create(Error& e)
{
    return new(e) LibSRTPInstance();
}

}
}
}

// EOF
