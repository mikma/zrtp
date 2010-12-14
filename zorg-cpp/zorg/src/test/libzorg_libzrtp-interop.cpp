#define NOMINMAX

#include <memory>
#include <deque>
#include <queue>
#include <functional>
#include <algorithm>

#include <stdio.h>

#include <zrtp.h>

#include <zorg/zorg.h>
#include <zorg/crypto.h>
#include <zorg/zrtp.h>

// FIXME: this sucks
namespace ZORG
{
namespace Crypto
{

namespace Libsrtp { CipherFunction * CreateAES1(Error& e); }

namespace OpenSSL
{
    KeyExchangeFunction * CreateDH3k(Error& e);
}

namespace Impl
{
    HashFunction * CreateS256(Error& e);
    SASFunction * CreateB32(Error& e);
    SASFunction * CreateB256(Error& e);
    RNGFunction * CreateRNGFunction(Error& e);
}

}
}

// FIXME: this sucks
namespace ZORG
{
namespace ZRTP
{
namespace Impl
{
Cache * CreateCache(::ZORG::Error &e, const char * file, CryptoSuite * cryptoSuite);
}
}
}

// FIXME: this sucks too
namespace ZORG
{
namespace SRTP
{
namespace Libsrtp
{
void Init(Error& e);
void Deinit();
SRTPInstance * Create(Error& e);
}
}
}

using namespace ::ZORG;
using namespace ::ZORG::Crypto;
using namespace ::ZORG::ZRTP;

namespace
{

class WorkItem
{
public:
    virtual ~WorkItem() {}
    virtual void run() = 0;
};

class IoTarget
{
public:
    virtual void writePacket(void * p, size_t n) = 0;
};

class PendingPacket: public WorkItem
{
private:
    size_t bufferSize;
    unsigned char buffer[5000];
    IoTarget * target;

public:
    PendingPacket(IoTarget * target, const void * p, size_t& n): target(target), bufferSize(std::min(n, sizeof(buffer)))
    {
	memcpy(buffer, p, bufferSize);
	n = bufferSize;
    }

    virtual void run()
    {
	target->writePacket(buffer, bufferSize);
    }
};

class SimulatorState
{
private:
    std::deque<std::pair<void *, WorkItem *> > workQueue;

    struct MatchByTaskId: public std::unary_function<std::pair<void *, WorkItem *>, bool>
    {
    private:
	void * desiredTaskId;

    public:
	MatchByTaskId(void * desiredTaskId): desiredTaskId(desiredTaskId) {}
	bool operator()(const std::pair<void *, WorkItem *>& item) { return item.first == desiredTaskId; }
    };

public:
    ~SimulatorState()
    {
	for(WorkItem * workItem = dequeueTask(); workItem != NULL; workItem = dequeueTask())
	    delete workItem;
    }

public:
    void * enqueueTask(WorkItem * workItem, void * taskId = NULL)
    {
	if(taskId == NULL)
	    taskId = workItem;

	workQueue.push_back(std::make_pair(taskId, workItem));
	return taskId;
    }

    void cancelTask(void * taskId)
    {
	std::deque<std::pair<void *, WorkItem *> >::const_iterator p = std::find_if(workQueue.begin(), workQueue.end(), MatchByTaskId(taskId));

	if(p != workQueue.end())
	{
	    delete p->second;
	    workQueue.erase(p);
	}
    }

    WorkItem * dequeueTask()
    {
	if(workQueue.empty())
	    return NULL;

	WorkItem * workItem = workQueue.front().second;
	workQueue.pop_front();

	return workItem;
    }

private:
    IoTarget * targetA;
    IoTarget * targetB;

public:
    void setIoTargetA(IoTarget * value) { targetA = value; }
    void setIoTargetB(IoTarget * value) { targetB = value; }

    size_t writeToA(const void * data, size_t size)
    {
	enqueueTask(new PendingPacket(targetA, data, size));
	return size;
    }

    size_t writeToB(const void * data, size_t size)
    {
	enqueueTask(new PendingPacket(targetB, data, size));
	return size;
    }
};

class libzrtp_WorkItem: public WorkItem
{
private:
    zrtp_stream_t * stream;
    zrtp_retry_task_t * task;

public:
    virtual void run() { task->callback(stream, task); }
    libzrtp_WorkItem(zrtp_stream_t * stream, zrtp_retry_task_t * task): stream(stream), task(task) {}
};

zrtp_status_t libzrtp_sched_on_init(zrtp_global_t * zrtp)
{
    // TODO?
    return zrtp_status_ok;
}

void libzrtp_sched_on_down()
{
    // TODO?
}

void libzrtp_sched_on_call_later(zrtp_stream_t * stream, zrtp_retry_task_t * task)
{
    SimulatorState& state = *static_cast<SimulatorState *>(zrtp_stream_get_userdata(stream));
    state.enqueueTask(new libzrtp_WorkItem(stream, task), task);
}

void libzrtp_sched_on_cancel_call_later(zrtp_stream_t * ctx, zrtp_retry_task_t * task)
{
    SimulatorState& state = *static_cast<SimulatorState *>(zrtp_stream_get_userdata(ctx));
    state.cancelTask(task);
}

void libzrtp_sched_on_wait_call_later(zrtp_stream_t * stream)
{
    // TODO?
}

int libzrtp_misc_on_send_packet(const zrtp_stream_t * stream, char * packet, unsigned int length)
{
    SimulatorState& state = *static_cast<SimulatorState *>(zrtp_stream_get_userdata(stream));
    return state.writeToB(packet, length);
}

class libzrtp_IoTarget: public IoTarget
{
private:
    zrtp_stream_t * stream;

public:
    libzrtp_IoTarget(zrtp_stream_t * stream): stream(stream) {}

    virtual void writePacket(void * p, size_t n)
    {
	unsigned int size = static_cast<unsigned int>(n);
	zrtp_status_t status = zrtp_process_srtp(stream, static_cast<char *>(p), &size);
    }
};

class libzorg_IoTarget: public IoTarget
{
private:
    Stream * stream;

public:
    libzorg_IoTarget(Stream * stream): stream(stream) {}

    virtual void writePacket(void * p, size_t n)
    {
	ZORG_DECL_ERROR(e);

	Blob packet;
	packet.dataSize = n;
	packet.maxSize = n;
	packet.buffer = p;

	stream->unprotectSRTP_InPlace(e, packet);
    }
};

class libzorg_WorkItem: public WorkItem
{
private:
    Task * task;

public:
    libzorg_WorkItem(Task * task): task(task) {}

    virtual ~libzorg_WorkItem()
    {
	if(task)
	    task->cancel();
    }

    virtual void run()
    {
	assert(task);
	task->run();
	task = NULL;
    }
};

class libzorg_Interface: public SessionInterface, public StreamInterface
{
private:
    SimulatorState& state;

public:
    libzorg_Interface(SimulatorState& state): state(state) {}

    virtual TaskCookie * runTask(::ZORG::Error& e, Task * task, int)
    {
	if(ZORG_FAILURE(e))
	    return NULL;

	return static_cast<TaskCookie *>(state.enqueueTask(new libzorg_WorkItem(task)));
    }

    virtual void cancelTask(::ZORG::Error& e, TaskCookie * taskId)
    {
	if(ZORG_FAILURE(e))
	    return;

	state.cancelTask(taskId);
    }

    virtual void cancelAllTasks()
    {
	// TODO
    }

    virtual void sendMessage(::ZORG::Error& e, Stream *, const Blob& messagePacket)
    {
	if(ZORG_FAILURE(e))
	    return;

	state.writeToA(messagePacket.buffer, messagePacket.dataSize);
    }

    virtual void onProtocolEvent(Stream * stream, Event evt)
    {
	// TODO
    }

    virtual void onSecurityEvent(Stream * stream, SecurityEvent evt)
    {
	// TODO
    }
};

class libzorg_CryptoSuite: public CryptoSuite
{
private:
    std::auto_ptr<RNGFunction> m_rngFunction;

public:
    libzorg_CryptoSuite(::ZORG::Error& e): m_rngFunction(Crypto::Impl::CreateRNGFunction(e))
    {
	if(ZORG_FAILURE(e))
	    return;
    }

    virtual RNG * createRNG(::ZORG::Error& e)
    {
	if(ZORG_FAILURE(e))
	    return NULL;

	return m_rngFunction->Create(e);
    }

    virtual Crypto::HashFunction * createHashFunction(::ZORG::Error& e, HashAlgorithm hashAlgorithm)
    {
	if(ZORG_FAILURE(e))
	    return NULL;

	switch(hashAlgorithm)
	{
	case HashS256:
	    return Crypto::Impl::CreateS256(e);

	default:
	    ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	    return NULL;
	}
    }

    virtual Crypto::CipherFunction * createCipherFunction(::ZORG::Error& e, CipherAlgorithm cipherAlgorithm)
    {
	if(ZORG_FAILURE(e))
	    return NULL;

	switch(cipherAlgorithm)
	{
	case CipherAES1:
	    return Libsrtp::CreateAES1(e);

	default:
	    ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	    return NULL;
	}
    }

    virtual Crypto::KeyExchangeFunction * createKeyAgreementFunction(::ZORG::Error& e, KeyAgreementType keyAgreementType, RNG * rng)
    {
	if(ZORG_FAILURE(e))
	    return NULL;

	switch(keyAgreementType)
	{
	case KeyAgreementDH3k:
	    return OpenSSL::CreateDH3k(e);

	default:
	    ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	    return NULL;
	}
    }

    virtual Crypto::SASFunction * createSASFunction(::ZORG::Error& e, SASType sasType)
    {
	if(ZORG_FAILURE(e))
	    return NULL;

	switch(sasType)
	{
	case SASB32:
	    return Crypto::Impl::CreateB32(e);

	case SASB256:
	    return Crypto::Impl::CreateB256(e);

	default:
	    ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	    return NULL;
	}
    }
};

}

int main()
{
    SimulatorState state;

    zrtp_zid_t libzrtp_zid;
    memset(&libzrtp_zid, 1, sizeof(libzrtp_zid));

    ZID libzorg_zid;
    memset(&libzorg_zid, 2, sizeof(libzorg_zid));

    uint32_t libzrtp_ssrc;
    memset(&libzrtp_ssrc, 1, sizeof(libzrtp_ssrc));

    SSRC libzorg_ssrc;
    memset(&libzorg_ssrc, 2, sizeof(libzorg_ssrc));

    // initialize libraries
    zrtp_global_t * libzrtp;
    std::auto_ptr<Instance> libzorg;

    zrtp_status_t status;
    ZORG_DECL_ERROR(e);

    zrtp_config_t libzrtp_config;
    zrtp_config_defaults(&libzrtp_config);
    libzrtp_config.lic_mode = ZRTP_LICENSE_MODE_UNLIMITED; /////////////////////
    libzrtp_config.cb.sched_cb.on_init = &libzrtp_sched_on_init;
    libzrtp_config.cb.sched_cb.on_down = &libzrtp_sched_on_down;
    libzrtp_config.cb.sched_cb.on_call_later = &libzrtp_sched_on_call_later;
    libzrtp_config.cb.sched_cb.on_cancel_call_later = &libzrtp_sched_on_cancel_call_later;
    libzrtp_config.cb.sched_cb.on_wait_call_later = &libzrtp_sched_on_wait_call_later;
    libzrtp_config.cb.misc_cb.on_send_packet = &libzrtp_misc_on_send_packet;
    status = zrtp_init(&libzrtp_config, &libzrtp);

    libzorg_CryptoSuite libzorg_crypt(e);
    std::auto_ptr<Cache> libzorg_cache(ZRTP::Impl::CreateCache(e, "./zorg_cache", &libzorg_crypt));

    SRTP::Libsrtp::Init(e);
    libzorg.reset(Instance::Create(e, &libzorg_crypt, SRTP::Libsrtp::Create(e)));

    libzorg_Interface libzorg_iface((state));

    // create sessions
    zrtp_session_t * libzrtp_session;
    std::auto_ptr<Session> libzorg_session;

    zrtp_profile_t libzrtp_profile;
    zrtp_profile_defaults(&libzrtp_profile, libzrtp);
    libzrtp_profile.autosecure = 1; ///////////////////
    status = zrtp_session_init(libzrtp, &libzrtp_profile, libzrtp_zid, 1, &libzrtp_session);
    zrtp_session_set_userdata(libzrtp_session, &state);

    Profile libzorg_profile = Profile::Default();
    libzorg_session.reset(libzorg->createSession(e, &libzorg_iface, libzorg_cache.get(), libzorg_zid, libzorg_profile));

    // create streams
    zrtp_stream_t * libzrtp_stream;
    std::auto_ptr<Stream> libzorg_stream;

    status = zrtp_stream_attach(libzrtp_session, &libzrtp_stream);
    zrtp_stream_set_userdata(libzrtp_stream, &state);

    libzrtp_IoTarget libzrtp_io_target((libzrtp_stream));
    state.setIoTargetA(&libzrtp_io_target);

    libzorg_stream.reset(libzorg_session->createStream(e, &libzorg_iface));

    libzorg_IoTarget libzorg_io_target((libzorg_stream.get()));
    state.setIoTargetB(&libzorg_io_target);

    // start streams
    status = zrtp_stream_start(libzrtp_stream, libzrtp_ssrc);
    libzorg_stream->start(e, libzorg_ssrc);

    // message loop
    for(WorkItem * item = state.dequeueTask(); item; item = state.dequeueTask())
    {
	item->run();
	delete item;
    }
}

// EOF
