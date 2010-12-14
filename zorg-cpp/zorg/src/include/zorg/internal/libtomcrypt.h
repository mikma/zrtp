#ifndef ZORG_INTERNAL_LIBTOMCRYPT_H_
#define ZORG_INTERNAL_LIBTOMCRYPT_H_

#include <zorg/zorg.h>

namespace ZORG
{
namespace LibTomCrypt
{
ErrorCode convertErrorCode(int e);
}
}

#endif

// EOF
