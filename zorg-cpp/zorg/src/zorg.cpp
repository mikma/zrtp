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

#include <new>
#include <string.h>
#include <stdlib.h>
#include <zorg/zorg.h>

#ifdef _DEBUG
void Zorg_DebugSetError(Zorg_Error * e, enum Zorg_ErrorCode code, const char * file, int line)
{
    e->code_ = code;
    e->file_ = file;
    e->line_ = line;
}
#endif

namespace ZORG
{

const Blob& copy(::ZORG::Error& e, const Blob& src, Blob& dest)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    if(src.dataSize > dest.maxSize)
    {
	ZORG_SET_ERROR(e, ErrorBufferSize);
	return NullBlob;
    }

    memcpy(dest.buffer, src.buffer, src.dataSize);
    dest.dataSize = src.dataSize;

    return dest;
}

const Blob& truncatedCopy(::ZORG::Error& e, const Blob& src, Blob& dest)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    if(src.dataSize < dest.maxSize)
    {
	ZORG_SET_ERROR(e, ErrorDataSize);
	return NullBlob;
    }

    memcpy(dest.buffer, src.buffer, dest.maxSize);
    dest.dataSize = dest.maxSize;

    return dest;
}

const Blob& fillCopy(::ZORG::Error& e, const Blob& src, Blob& dest, uint8_t fillByte)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    size_t dataSize = std::min(src.dataSize, dest.maxSize);

    memcpy(dest.buffer, src.buffer, dataSize);
    memset(static_cast<char *>(dest.buffer) + dataSize, fillByte, dest.maxSize - dataSize);

    dest.dataSize = dest.maxSize;

    return dest;
}

const Blob& wipeData(Blob& dest)
{
    volatile unsigned char * p = static_cast<unsigned char *>(dest.buffer);
    volatile unsigned char * end = p + dest.dataSize;

    for(; p != end; ++ p)
	*p = 0;

    return dest;
}

const Blob NullBlob = { 0, 0, 0 };
const Blob EmptyBlob = { 0, 0, const_cast<char *>("") };

}

void * operator new(size_t n, ::ZORG::Error& e) throw()
{
    if(ZORG_FAILURE(e))
	return NULL;

    void * p = ::operator new(n, std::nothrow_t());

    if(p == NULL)
	ZORG_SET_ERROR(e, ZORG::ErrorNoMemory);

    return p;
}

void * operator new[](size_t n, ::ZORG::Error& e) throw()
{
    if(ZORG_FAILURE(e))
	return NULL;

    void * p = ::operator new(n, std::nothrow_t());

    if(p == NULL)
	ZORG_SET_ERROR(e, ZORG::ErrorNoMemory);

    return p;
}

void operator delete(void * p, ::ZORG::Error&)
{
    ::operator delete(p);
}

void operator delete[](void * p, ::ZORG::Error&)
{
    ::operator delete(p);
}

// EOF
