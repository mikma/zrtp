#include <stdint.h>

#include <zorg/zorg.h>
#include <zorg/crypto.h>

namespace ZORG
{
namespace Crypto
{
namespace Impl
{
class SAS32: public ::ZORG::Crypto::SASFunction
{
public:
    virtual const SAS& render(Error& e, const SASValue& sasValue, SAS& sas)
    {
	if(ZORG_FAILURE(e))
	    return sas;

        uint32_t sasValueBits =
            (uint32_t(sasValue.bytes[3]) <<  0) |
            (uint32_t(sasValue.bytes[2]) <<  8) |
            (uint32_t(sasValue.bytes[1]) << 16) |
            (uint32_t(sasValue.bytes[0]) << 24);

        for(unsigned i = 0, shift = 27; i < 4; ++ i, shift -= 5)
            sas.b32buf_[i] = "ybndrfg8ejkmcpqxot1uwisza345h769"[(sasValueBits >> shift) & 0x1f];

        sas.sas1.dataSize = 4;
        sas.sas1.maxSize = 5;
        sas.sas1.buffer = sas.b32buf_;
	sas.sas2 = NullBlob;

        return sas;
    }
};

class SAS256: public ::ZORG::Crypto::SASFunction
{
public:
    virtual const SAS& render(Error& e, const SASValue& sasValue, SAS& sas)
    {
	if(ZORG_FAILURE(e))
	    return sas;

	sas.sas1 = ::ZORG::Crypto::PGPWordList::EvenWords[sasValue.bytes[0]];
        sas.sas2 = ::ZORG::Crypto::PGPWordList::OddWords[sasValue.bytes[1]];
        return sas;
    }
};

SASFunction * CreateB32(Error& e)
{
    return new(e) SAS32();
}

SASFunction * CreateB256(Error& e)
{
    return new(e) SAS256();
}

}
}
}

// EOF
