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

#include <string.h>

#include <zorg/zrtp.h>
#include <zorg/srtp.h>
#include <zorg/crypto.h>

#include <memory>

using namespace ZORG;
using namespace ZORG::Crypto;
using namespace ZORG::ZRTP;
using namespace ZORG::SRTP;

namespace
{
void Zorg_Profile_Import(const Zorg_Profile& from, Profile& to)
{
    to.autoSecure = !!from.autoSecure;
    to.disclose = !!from.disclose;
    to.fastAcknowledge = !!from.fastAcknowledge;
    to.hashAlgorithmsImplyMandatory = !!from.hashAlgorithmsImplyMandatory;
    to.cipherAlgorithmsImplyMandatory = !!from.cipherAlgorithmsImplyMandatory;
    to.authTagTypesImplyMandatory = !!from.authTagTypesImplyMandatory;
    to.keyAgreementTypesImplyMandatory = !!from.keyAgreementTypesImplyMandatory;
    to.sasTypesImplyMandatory = !!from.sasTypesImplyMandatory;

    for(unsigned i = 0; i < Zorg_Profile_ComponentsMaxCount; ++ i)
    {
        if(from.hashAlgorithms[i] != Zorg_HashUnknown)
    	    to.hashAlgorithms += from.hashAlgorithms[i];
    }

    for(unsigned i = 0; i < Zorg_Profile_ComponentsMaxCount; ++ i)
    {
        if(from.cipherAlgorithms[i] != Zorg_CipherUnknown)
    	    to.cipherAlgorithms += from.cipherAlgorithms[i];
    }

    for(unsigned i = 0; i < Zorg_Profile_ComponentsMaxCount; ++ i)
    {
        if(from.authTagTypes[i] != Zorg_AuthTagUnknown)
    	    to.authTagTypes += from.authTagTypes[i];
    }

    for(unsigned i = 0; i < Zorg_Profile_ComponentsMaxCount; ++ i)
    {
        if(from.keyAgreementTypes[i] != Zorg_KeyAgreementUnknown)
    	    to.keyAgreementTypes += from.keyAgreementTypes[i];
    }

    for(unsigned i = 0; i < Zorg_Profile_ComponentsMaxCount; ++ i)
    {
        if(from.sasTypes[i] != Zorg_SASUnknown)
    	    to.sasTypes += from.sasTypes[i];
    }

    to.expireTime = from.expireTime;
    memcpy(&to.clientId, &from.clientId, sizeof(to.clientId));
}

template<class InIter, class OutIter, class FillT>
void checkedCopyFillBack(InIter beginIn, InIter endIn, OutIter beginOut, OutIter endOut, const FillT& fillValue)
{
    InIter in = beginIn;
    OutIter out = beginOut;

    while(in != endIn && out != endOut)
	*out ++ = *in ++;

    while(out != endOut)
	*out ++ = fillValue;
}

template<class T, size_t N>
T * arrayBegin(T (& arr)[N])
{
    return &arr[0];
}

template<class T, size_t N>
T * arrayEnd(T (& arr)[N])
{
    return &arr[N];
}

void Zorg_Profile_Export(const Profile& from, Zorg_Profile& to)
{
    to.autoSecure = !!from.autoSecure;
    to.disclose = !!from.disclose;
    to.fastAcknowledge = !!from.fastAcknowledge;
    to.hashAlgorithmsImplyMandatory = !!from.hashAlgorithmsImplyMandatory;
    to.cipherAlgorithmsImplyMandatory = !!from.cipherAlgorithmsImplyMandatory;
    to.authTagTypesImplyMandatory = !!from.authTagTypesImplyMandatory;
    to.keyAgreementTypesImplyMandatory = !!from.keyAgreementTypesImplyMandatory;
    to.sasTypesImplyMandatory = !!from.sasTypesImplyMandatory;
    checkedCopyFillBack(from.hashAlgorithms.begin(), from.hashAlgorithms.end(), arrayBegin(to.hashAlgorithms), arrayEnd(to.hashAlgorithms), HashUnknown);
    checkedCopyFillBack(from.cipherAlgorithms.begin(), from.cipherAlgorithms.end(), arrayBegin(to.cipherAlgorithms), arrayEnd(to.cipherAlgorithms), CipherUnknown);
    checkedCopyFillBack(from.authTagTypes.begin(), from.authTagTypes.end(), arrayBegin(to.authTagTypes), arrayEnd(to.authTagTypes), AuthTagUnknown);
    checkedCopyFillBack(from.keyAgreementTypes.begin(), from.keyAgreementTypes.end(), arrayBegin(to.keyAgreementTypes), arrayEnd(to.keyAgreementTypes), KeyAgreementUnknown);
    checkedCopyFillBack(from.sasTypes.begin(), from.sasTypes.end(), arrayBegin(to.sasTypes), arrayEnd(to.sasTypes), SASUnknown);
    to.expireTime = from.expireTime;
    memcpy(&to.clientId, &from.clientId, sizeof(to.clientId));
}
}

struct Zorg
{
    std::auto_ptr<Instance> instance;
    void * userData;

    Zorg(::ZORG::Error& e, CryptoSuite * cryptoSuite, SRTPInstance * srtpImpl, void * userData): instance(Instance::Create(e, cryptoSuite, srtpImpl)), userData(userData)
    {
    }
};

struct Zorg_Session: public SessionInterface
{
    Zorg * zorg;
    std::auto_ptr<Session> session;
    const Zorg_SessionInterface * iface;
    void * userData;

    Zorg_Session(::ZORG::Error& e, Zorg * zorg, const Zorg_SessionInterface * iface, Zorg_Cache * cache, const struct Zorg_ZID * zid, const struct Zorg_Profile * profile, int isInitiator, void * userData): zorg(zorg), iface(iface), userData(userData)
    {
	if(ZORG_FAILURE(e))
	    return;

        Profile tmp = Profile();
	Zorg_Profile_Import(*profile, tmp);

	session.reset(zorg->instance->createSession(e, this, cache, *reinterpret_cast<const ZID *>(zid), tmp, !!isInitiator));
    }

    virtual TaskCookie * runTask(::ZORG::Error& e, Task * task, int delay)
    {
	if(ZORG_FAILURE(e))
	    return NULL;

	return iface->runTask(&e, this, task, delay);
    }

    virtual void cancelTask(::ZORG::Error& e, TaskCookie * taskId)
    {
	if(ZORG_FAILURE(e))
	    return;

	iface->cancelTask(&e, this, taskId);
    }

    virtual void cancelAllTasks()
    {
	iface->cancelAllTasks(this);
    }
};

struct Zorg_Stream: public StreamInterface
{
    Zorg_Session * session;
    std::auto_ptr<Stream> stream;
    const Zorg_StreamInterface * iface;
    void * userData;

    Zorg_Stream(::ZORG::Error& e, Zorg_Session * session, const Zorg_StreamInterface * iface, void * userData): session(session), iface(iface), userData(userData)
    {
	if(ZORG_FAILURE(e))
	    return;

	stream.reset(session->session->createStream(e, this));
    }

    virtual void sendMessage(::ZORG::Error& e, Stream *, const Blob& messagePacket)
    {
	if(ZORG_FAILURE(e))
	    return;

	iface->sendMessage(&e, this, &messagePacket);
    }

    virtual void onProtocolEvent(Stream *, Event evt)
    {
	iface->onProtocolEvent(this, evt);
    }

    virtual void onSecurityEvent(Stream *, SecurityEvent evt)
    {
	iface->onSecurityEvent(this, evt);
    }
};

struct Zorg_CryptoSuite;
struct Zorg_Cache;
struct Zorg_SRTP;

extern "C"
{

Zorg * Zorg_Create(struct Zorg_Error * e, Zorg_CryptoSuite * cryptoSuite, Zorg_SRTP * srtpImpl, void * userData)
{
    return guard_new(*e, new(*e) Zorg(*e, cryptoSuite, srtpImpl, userData));
}

void Zorg_Destroy(Zorg * zorg)
{
    delete zorg;
}

void Zorg_SetUserData(Zorg * zorg, void * userData)
{
    zorg->userData = userData;
}

void * Zorg_GetUserData(Zorg * zorg)
{
    return zorg->userData;
}

void Zorg_AddEntropy(struct Zorg_Error * e, Zorg * zorg, const struct Zorg_Blob * seed)
{
    if(ZORG_FAILURE(*e))
	return;

    zorg->instance->addEntropy(*e, *seed);
}

const struct Zorg_Blob * Zorg_GenerateRandom(struct Zorg_Error * e, Zorg * zorg, size_t nbyte, struct Zorg_Blob * randbuf)
{
    if(ZORG_FAILURE(*e))
	return &NullBlob;

    return &zorg->instance->generateRandom(*e, nbyte, *randbuf);
}

Zorg_Session * Zorg_CreateSession(struct Zorg_Error * e, Zorg * zorg, const Zorg_SessionInterface * iface, Zorg_Cache * cache, const struct Zorg_ZID * zid, const struct Zorg_Profile * profile, int isInitiator, void * userData)
{
    return guard_new(*e, new(*e) Zorg_Session(*e, zorg, iface, cache, zid, profile, isInitiator, userData));
}

void Zorg_Session_Destroy(Zorg_Session * session)
{
    delete session;
}

void Zorg_Session_SetUserData(Zorg_Session * session, void * userData)
{
    session->userData = userData;
}

void * Zorg_Session_GetUserData(Zorg_Session * session)
{
    return session->userData;
}

Zorg * Zorg_Session_GetZorg(Zorg_Session * session)
{
    return session->zorg;
}

struct Zorg_ZID Zorg_Session_GetZID(Zorg_Session * session)
{
    return reinterpret_cast<const Zorg_ZID&>(session->session->zid());
}

struct Zorg_ZID Zorg_Session_GetPeerZID(struct Zorg_Error * e, Zorg_Session * session)
{
    if(ZORG_FAILURE(*e))
	return Zorg_ZID();

    return reinterpret_cast<const Zorg_ZID&>(session->session->peerZID(*e));
}

struct Zorg_SASValue Zorg_Session_GetSASValue(struct Zorg_Error * e, Zorg_Session * session)
{
    Crypto::SASValue tmp;
    Zorg_SASValue sasValue = {};
    
    if(ZORG_SUCCESS(*e))
	tmp = session->session->sasValue(*e);

    if(ZORG_SUCCESS(*e))
	memcpy(&sasValue, tmp.bytes, sizeof(sasValue));

    return sasValue;
}

const struct Zorg_SAS * Zorg_Session_GetSAS(struct Zorg_Error * e, Zorg_Session * session, struct Zorg_SAS * sas)
{
    if(ZORG_SUCCESS(*e))
	session->session->sas(*e, *sas);

    return sas;
}

int Zorg_Session_GetSASVerified(struct Zorg_Error * e, Zorg_Session * session)
{
    if(ZORG_FAILURE(*e))
	return 0;

    return !!session->session->sasVerified(*e);
}

void Zorg_Session_SetSASVerified(struct Zorg_Error * e, Zorg_Session * session, int isVerified)
{
    if(ZORG_FAILURE(*e))
	return;

    session->session->setSASVerified(*e, !!isVerified);
}


Zorg_Stream * Zorg_Session_CreateStream(struct Zorg_Error * e, Zorg_Session * session, const Zorg_StreamInterface * iface, void * userData)
{
    return guard_new(*e, new(*e) Zorg_Stream(*e, session, iface, userData));
}

void Zorg_Stream_Destroy(Zorg_Stream * stream)
{
    delete stream;
}

void Zorg_Stream_SetUserData(Zorg_Stream * stream, void * userData)
{
    stream->userData = userData;
}

void * Zorg_Stream_GetUserData(Zorg_Stream * stream)
{
    return stream->userData;
}

Zorg_Session * Zorg_Stream_GetSession(Zorg_Stream * stream)
{
    return stream->session;
}

void Zorg_Stream_Start(struct Zorg_Error * e, Zorg_Stream * stream, const struct Zorg_SSRC * ssrc)
{
    if(ZORG_FAILURE(*e))
	return;

    stream->stream->start(*e, reinterpret_cast<const SSRC&>(*ssrc));
}

void Zorg_Stream_Stop(Zorg_Stream * stream)
{
    stream->stream->stop();
}

void Zorg_Stream_Halt(struct Zorg_Error * e, Zorg_Stream * stream, const struct Zorg_Error * stopError)
{
    if(ZORG_FAILURE(*e))
	return;

    stream->stream->halt(*e, *stopError);
}

const struct Zorg_Blob * Zorg_Stream_GetSDPZrtpHash(struct Zorg_Error * e, Zorg_Stream * stream, struct Zorg_Blob * helloHash)
{
    if(ZORG_FAILURE(*e))
	return &NullBlob;

    return &stream->stream->getSDPZrtpHash(*e, *helloHash);
}

void Zorg_Stream_SetPeerSDPZrtpHash(struct Zorg_Error * e, Zorg_Stream * stream, const struct Zorg_Blob * peerHelloHash)
{
    if(ZORG_FAILURE(*e))
	return;

    stream->stream->setPeerSDPZrtpHash(*e, *peerHelloHash);
}

const struct Zorg_Blob * Zorg_Stream_ProtectRTP_InPlace(struct Zorg_Error * e, Zorg_Stream * stream, struct Zorg_Blob * rtpPacket)
{
    if(ZORG_FAILURE(*e))
	return &NullBlob;

    return &stream->stream->protectRTP_InPlace(*e, *rtpPacket);
}

const struct Zorg_Blob * Zorg_Stream_ProtectRTCP_InPlace(struct Zorg_Error * e, Zorg_Stream * stream, struct Zorg_Blob * rtcpPacket)
{
    if(ZORG_FAILURE(*e))
	return &NullBlob;

    return &stream->stream->protectRTCP_InPlace(*e, *rtcpPacket);
}

const struct Zorg_Blob * Zorg_Stream_UnprotectSRTP_InPlace(struct Zorg_Error * e, Zorg_Stream * stream, struct Zorg_Blob * srtpPacket)
{
    if(ZORG_FAILURE(*e))
	return &NullBlob;

    return &stream->stream->unprotectSRTP_InPlace(*e, *srtpPacket);
}

const struct Zorg_Blob * Zorg_Stream_UnprotectSRTCP_InPlace(struct Zorg_Error * e, Zorg_Stream * stream, struct Zorg_Blob * srtcpPacket)
{
    if(ZORG_FAILURE(*e))
	return &NullBlob;

    return &stream->stream->unprotectSRTCP_InPlace(*e, *srtcpPacket);
}

void Zorg_Task_Run(Zorg_Task * task)
{
    task->run();
}

void Zorg_Task_Cancel(Zorg_Task * task)
{
    task->cancel();
}

int Zorg_Profile_Check(Zorg_Error * e, const struct Zorg_Profile * profile)
{
    if(ZORG_FAILURE(*e))
	return 0;

    Profile tmp = Profile();
    Zorg_Profile_Import(*profile, tmp);

    return tmp.check(*e);
}

void Zorg_Profile_Default(struct Zorg_Profile * profile)
{
    Profile tmp = Profile::Default();
    Zorg_Profile_Export(tmp, *profile);
}

}

// EOF
