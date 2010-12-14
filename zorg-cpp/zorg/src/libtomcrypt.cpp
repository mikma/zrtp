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

#include <zorg/zorg.h>
#include <zorg/internal/libtomcrypt.h>

#include <tomcrypt.h>

namespace ZORG
{
namespace LibTomCrypt
{
ErrorCode convertErrorCode(int e)
{
    switch(e)
    {
    case CRYPT_OK: return ErrorNone;
    case CRYPT_ERROR: return ErrorCrypto;
    case CRYPT_NOP: return ErrorNone;
    case CRYPT_INVALID_KEYSIZE: return ErrorKeySize;
    case CRYPT_INVALID_ROUNDS: return ErrorArgument;
    case CRYPT_FAIL_TESTVECTOR: return ErrorCrypto;
    case CRYPT_BUFFER_OVERFLOW: return ErrorBufferSize;
    case CRYPT_INVALID_PACKET: return ErrorDataSize;
    case CRYPT_INVALID_PRNGSIZE: return ErrorArgument;
    case CRYPT_ERROR_READPRNG: return ErrorCrypto;
    case CRYPT_INVALID_CIPHER: return ErrorArgument;
    case CRYPT_INVALID_HASH: return ErrorArgument;
    case CRYPT_INVALID_PRNG: return ErrorArgument;
    case CRYPT_MEM: return ErrorNoMemory;
    case CRYPT_INVALID_ARG: return ErrorArgument;
    case CRYPT_FILE_NOTFOUND: return ErrorFileSystem;
    case CRYPT_INVALID_PRIME_SIZE: return ErrorArgument;

    case CRYPT_PK_TYPE_MISMATCH:
    case CRYPT_PK_NOT_PRIVATE:
    case CRYPT_PK_INVALID_TYPE:
    case CRYPT_PK_INVALID_SYSTEM:
    case CRYPT_PK_DUP:
    case CRYPT_PK_NOT_FOUND:
    case CRYPT_PK_INVALID_SIZE:
    case CRYPT_PK_INVALID_PADDING:
	ZORG_UNREACHABLE();
	return ErrorInternal;

    default:
	ZORG_UNREACHABLE();
	return ErrorCrypto;
    }
}
}
}

// EOF
