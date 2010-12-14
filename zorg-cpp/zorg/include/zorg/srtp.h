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

#ifndef ZORG_SRTP_H_
#define ZORG_SRTP_H_

#include <string.h>
#include <zorg/zorg.h>
#include <zorg/crypto.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct Zorg_SRTP;
typedef struct Zorg_SRTP Zorg_SRTP;

#ifdef __cplusplus
}
#endif

#if defined(__cplusplus) && !defined(ZORG_C_API)

namespace ZORG
{
namespace SRTP
{

class SRTPContext
{
protected:
    SRTPContext() {}

public:
    virtual ~SRTPContext() {}

    virtual const Blob& protectRTP_InPlace(Error& e, Blob& rtpPacket)
    {
        return protectRTP(e, rtpPacket, rtpPacket);
    }

    virtual const Blob& unprotectRTP_InPlace(Error& e, Blob& srtpPacket)
    {
        return unprotectRTP(e, srtpPacket, srtpPacket);
    }

    virtual const Blob& protectRTCP_InPlace(Error& e, Blob& rtcpPacket)
    {
        return protectRTCP(e, rtcpPacket, rtcpPacket);
    }

    virtual const Blob& unprotectRTCP_InPlace(Error& e, Blob& srtpPacket)
    {
        return unprotectRTCP(e, srtpPacket, srtpPacket);
    }

    virtual const Blob& protectRTP(Error& e, const Blob& rtpPacket, Blob& srtpPacket)
    {
        if(ZORG_FAILURE(e))
	    return NullBlob;

        if(srtpPacket.maxSize < rtpPacket.dataSize)
	{
	    ZORG_SET_ERROR(e, ErrorBufferSize);
	    return NullBlob;
	}

        memcpy(srtpPacket.buffer, rtpPacket.buffer, rtpPacket.dataSize);
        srtpPacket.dataSize = rtpPacket.dataSize;
        protectRTP_InPlace(e, srtpPacket);
        return srtpPacket;
    }

    virtual const Blob& unprotectRTP(Error& e, const Blob& srtpPacket, Blob& rtpPacket)
    {
        if(ZORG_FAILURE(e))
	    return NullBlob;
        
	if(rtpPacket.maxSize < srtpPacket.dataSize)
	{
	    ZORG_SET_ERROR(e, ErrorBufferSize);
	    return NullBlob;
	}

        memcpy(rtpPacket.buffer, srtpPacket.buffer, srtpPacket.dataSize);
        rtpPacket.dataSize = srtpPacket.dataSize;
        unprotectRTP_InPlace(e, rtpPacket);
        return rtpPacket;
    }

    virtual const Blob& protectRTCP(Error& e, const Blob& rtcpPacket, Blob& srtpPacket)
    {
        if(ZORG_FAILURE(e))
	    return NullBlob;
        
	if(srtpPacket.maxSize < rtcpPacket.dataSize)
	{
	    ZORG_SET_ERROR(e, ErrorBufferSize);
	    return NullBlob;
	}

        memcpy(srtpPacket.buffer, rtcpPacket.buffer, rtcpPacket.dataSize);
        srtpPacket.dataSize = rtcpPacket.dataSize;
        protectRTCP_InPlace(e, srtpPacket);
        return srtpPacket;
    }

    virtual const Blob& unprotectRTCP(Error& e, const Blob& srtpPacket, Blob& rtcpPacket)
    {
        if(ZORG_FAILURE(e))
	    return NullBlob;

	if(rtcpPacket.maxSize < srtpPacket.dataSize)
	{
	    ZORG_SET_ERROR(e, ErrorBufferSize);
	    return NullBlob;
	}

        memcpy(rtcpPacket.buffer, srtpPacket.buffer, srtpPacket.dataSize);
        rtcpPacket.dataSize = srtpPacket.dataSize;
        unprotectRTCP_InPlace(e, rtcpPacket);
        return rtcpPacket;
    }
};

typedef ::Zorg_SRTP SRTPInstance;

}
}

struct Zorg_SRTP
{
public:
    virtual ~Zorg_SRTP() {}
    virtual ::ZORG::Crypto::RFC5764::SRTPProfileMask SupportedProfiles(const ::ZORG::Crypto::RFC5764::SRTPProfileMask& desired) = 0;
    virtual ::ZORG::SRTP::SRTPContext * Create(::ZORG::Error& e, ::ZORG::Crypto::RFC5764::SRTPProfile rtpPolicy, ::ZORG::Crypto::RFC5764::SRTPProfile rtcpPolicy, bool inbound, const ::ZORG::Blob& masterKey, const ::ZORG::Blob& masterSalt) = 0;
};

#endif

#endif

// EOF
