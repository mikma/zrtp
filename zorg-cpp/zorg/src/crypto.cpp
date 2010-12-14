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

#include <iterator>
#include <memory>

#include <zorg/zorg.h>
#include <zorg/crypto.h>

using namespace ZORG;
using namespace ZORG::Crypto;

namespace
{

template<class T, size_t N>
T * arrayBegin(T (& arr)[N])
{
    return &(arr[0]);
}

template<class T, size_t N>
T * arrayEnd(T (& arr)[N])
{
    return &(arr[N]);
}

class BlockIterator;

BlockIterator beginDataBlock(const Blob& data, size_t blockBits);
BlockIterator endDataBlock(const Blob& data, size_t blockBits);
BlockIterator beginBufferBlock(const Blob& data, size_t blockBits);
BlockIterator endBufferBlock(const Blob& data, size_t blockBits);

class BlockIterator: public std::iterator<std::forward_iterator_tag, const Blob>
{
private:
    friend BlockIterator beginDataBlock(const Blob& data, size_t blockBits);
    friend BlockIterator endDataBlock(const Blob& data, size_t blockBits);
    friend BlockIterator beginBufferBlock(const Blob& data, size_t blockBits);
    friend BlockIterator endBufferBlock(const Blob& data, size_t blockBits);

    Blob curBlock;
    char * const end;
    size_t const blockBytes;

    void set_block(char * p)
    {
	curBlock.buffer = p;
	curBlock.dataSize = cur_block_size();
    }

    size_t cur_block_size() const { return std::min<ptrdiff_t>(blockBytes, end - static_cast<char *>(curBlock.buffer)); }

    BlockIterator(char * p, char * end, size_t blockBits): end(end), blockBytes(roundUpBitsToBytes(blockBits))
    {
	assert(p <= end);
	set_block(p);
	curBlock.maxSize = blockBytes;
    }

public:
    BlockIterator(): curBlock(), end(), blockBytes() {}
    BlockIterator(const BlockIterator& other): curBlock(other.curBlock), end(other.end), blockBytes(other.blockBytes) {}

    const BlockIterator& operator=(const BlockIterator& other)
    {
	assert(end == other.end);
	assert(blockBytes == other.blockBytes);
	curBlock = other.curBlock;
	return *this;
    }

    bool operator==(const BlockIterator& other) const
    {
	assert(end == other.end);
	assert(blockBytes == other.blockBytes);
	return curBlock.buffer == other.curBlock.buffer;
    }

    bool operator!=(const BlockIterator& other) const { return !(*this == other); }

    const Blob& operator*() const { return curBlock; }
    const Blob * operator->() const { return &curBlock; }

    const BlockIterator& operator++()
    {
	set_block(static_cast<char *>(curBlock.buffer) + curBlock.dataSize);
	return *this;
    }

    BlockIterator operator++(int)
    {
	BlockIterator ret(*this);
	++ ret;
	return ret;
    }
};

BlockIterator beginDataBlock(const Blob& data, size_t blockBits)
{
    return BlockIterator(static_cast<char *>(data.buffer), static_cast<char *>(data.buffer) + data.dataSize, blockBits);
}

BlockIterator endDataBlock(const Blob& data, size_t blockBits)
{
    return BlockIterator(static_cast<char *>(data.buffer) + data.dataSize, static_cast<char *>(data.buffer) + data.dataSize, blockBits);
}

BlockIterator beginBufferBlock(const Blob& data, size_t blockBits)
{
    return BlockIterator(static_cast<char *>(data.buffer), static_cast<char *>(data.buffer) + data.maxSize, blockBits);
}

BlockIterator endBufferBlock(const Blob& data, size_t blockBits)
{
    return BlockIterator(static_cast<char *>(data.buffer) + data.maxSize, static_cast<char *>(data.buffer) + data.maxSize, blockBits);
}

};

const Blob& Cipher::process(Error& e, const Blob& input, Blob& output)
{
    if(ZORG_FAILURE(e))
	return NullBlob;

    if(output.maxSize < input.dataSize)
    {
	ZORG_SET_ERROR(e, ErrorBufferSize);
	return NullBlob;
    }

    size_t blockBits = this->getBlockBits();
    BlockIterator pInput = beginDataBlock(input, blockBits);
    BlockIterator endInput = endDataBlock(input, blockBits);
    BlockIterator pOutput = beginBufferBlock(input, blockBits);

    for(; pInput != endInput; ++ pInput, ++ pOutput)
    {
	this->processBlock(e, *pInput, *pOutput);

	if(ZORG_FAILURE(e))
	    return NullBlob;
    }

    return output;
}

namespace
{

struct HashTestVector
{
    Blob data;
    Blob expectedHash;
};

static const HashTestVector SHA256TestVectors[] =
{
    // source: various
    { EmptyBlob,                                             asBlob("\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55") },

    // source: febooti.com
    { asBlob("Test vector from febooti.com"),                asBlob("\x07\x7b\x18\xfe\x29\x03\x6a\xda\x48\x90\xbd\xec\x19\x21\x86\xe1\x06\x78\x59\x7a\x67\x88\x02\x90\x52\x1d\xf7\x0d\xf4\xba\xc9\xab") },

    // source: bichlmeier.info
    { asBlob("abc"),                                         asBlob("\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad") },
    { asBlob("message digest"),                              asBlob("\xf7\x84\x6f\x55\xcf\x23\xe1\x4e\xeb\xea\xb5\xb4\xe1\x55\x0c\xad\x5b\x50\x9e\x33\x48\xfb\xc4\xef\xa3\xa1\x41\x3d\x39\x3c\xb6\x50") },
    { asBlob("secure hash algorithm"),                       asBlob("\xf3\x0c\xeb\x2b\xb2\x82\x9e\x79\xe4\xca\x97\x53\xd3\x5a\x8e\xcc\x00\x26\x2d\x16\x4c\xc0\x77\x08\x02\x95\x38\x1c\xbd\x64\x3f\x0d") },
    { asBlob("SHA256 is considered to be safe"),             asBlob("\x68\x19\xd9\x15\xc7\x3f\x4d\x1e\x77\xe4\xe1\xb5\x2d\x1f\xa0\xf9\xcf\x9b\xea\xea\xd3\x93\x9f\x15\x87\x4b\xd9\x88\xe2\xa2\x36\x30") },
    { asBlob("abcdbcdecdefdefgefghfghighijhijkijkljklmklmn"
             "lmnomnopnopq"),                                asBlob("\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1") },
    { asBlob("For this sample, this 63-byte string will be"
             " used as input data"),                         asBlob("\xf0\x8a\x78\xcb\xba\xee\x08\x2b\x05\x2a\xe0\x70\x8f\x32\xfa\x1e\x50\xc5\xc4\x21\xaa\x77\x2b\xa5\xdb\xb4\x06\xa2\xea\x6b\xe3\x42") },
    { asBlob("This is exactly 64 bytes long, not counting "
             "the terminating byte"),                        asBlob("\xab\x64\xef\xf7\xe8\x8e\x2e\x46\x16\x5e\x29\xf2\xbc\xe4\x18\x26\xbd\x4c\x7b\x35\x52\xf6\xb3\x82\xa9\xe7\xd3\xaf\x47\xc2\x45\xf8") },
};

static const HashTestVector SHA384TestVectors[] =
{
    // source: various
    { EmptyBlob,                                             asBlob("\x38\xb0\x60\xa7\x51\xac\x96\x38\x4c\xd9\x32\x7e\xb1\xb1\xe3\x6a\x21\xfd\xb7\x11\x14\xbe\x07\x43"
                                                                    "\x4c\x0c\xc7\xbf\x63\xf6\xe1\xda\x27\x4e\xde\xbf\xe7\x6f\x65\xfb\xd5\x1a\xd2\xf1\x48\x98\xb9\x5b") },

    // source: febooti.com
    { asBlob("Test vector from febooti.com"),                asBlob("\x38\x8b\xb2\xd4\x87\xde\x48\x74\x0f\x45\xfc\xb4\x41\x52\xb0\xb6\x65\x42\x8c\x49\xde\xf1\xaa\xf7"
                                                                    "\xc7\xf0\x9a\x40\xc1\x0a\xff\x1c\xd7\xc3\xfe\x33\x25\x19\x3c\x4d\xd3\x5d\x4e\xaa\x03\x2f\x49\xb0") },

    // source: IETF RFC 4754
    { asBlob("abc"),                                         asBlob("\xCB\x00\x75\x3F\x45\xA3\x5E\x8B\xB5\xA0\x3D\x69\x9A\xC6\x50\x07\x27\x2C\x32\xAB\x0E\xDE\xD1\x63"
                                                                    "\x1A\x8B\x60\x5A\x43\xFF\x5B\xED\x80\x86\x07\x2B\xA1\xE7\xCC\x23\x58\xBA\xEC\xA1\x34\xC8\x25\xA7") },

    // source: bglibs (untroubled.org)
    { asBlob("abcdefghbcdefghicdefghijdefghijkefghijklfghi"
             "jklmghijklmnhijklmnoijklmnopjklmnopqklmnopqr"
	     "lmnopqrsmnopqrstnopqrstu"),                    asBlob("\x09\x33\x0c\x33\xf7\x11\x47\xe8\x3d\x19\x2f\xc7\x82\xcd\x1b\x47\x53\x11\x1b\x17\x3b\x3b\x05\xd2"
                                                                    "\x2f\xa0\x80\x86\xe3\xb0\xf7\x12\xfc\xc7\xc7\x1a\x55\x7e\x2d\xb9\x66\xc3\xe9\xfa\x91\x74\x60\x39") },
    { asBlob("abcdbcdecdefdefgefghfghighijhijkijkljklmklmn"
             "lmnomnopnopq"),                                asBlob("\x33\x91\xfd\xdd\xfc\x8d\xc7\x39\x37\x07\xa6\x5b\x1b\x47\x09\x39\x7c\xf8\xb1\xd1\x62\xaf\x05\xab"
                                                                    "\xfe\x8f\x45\x0d\xe5\xf3\x6b\xc6\xb0\x45\x5a\x85\x20\xbc\x4e\x6f\x5f\xe9\x5b\x1f\xe3\xc8\x45\x2b") },
    { asBlob("This is exactly 64 bytes long, not counting "
             "the terminating byte"),                        asBlob("\xe2\x8e\x35\xe2\x5a\x18\x74\x90\x8b\xf0\x95\x8b\xb0\x88\xb6\x9f\x3d\x74\x2a\x75\x3c\x86\x99\x3e"
                                                                    "\x9f\x4b\x1c\x4c\x21\x98\x8f\x95\x8b\xd1\xfe\x03\x15\xb1\x95\xac\xa7\xb0\x61\x21\x3a\xc2\xa9\xbd") },
    { asBlob("For this sample, this 63-byte string will be"
             " used as input data"),                         asBlob("\x37\xb4\x9e\xf3\xd0\x8d\xe5\x3e\x9b\xd0\x18\xb0\x63\x00\x67\xbd\x43\xd0\x9c\x42\x7d\x06\xb0\x58"
                                                                    "\x12\xf4\x85\x31\xbc\xe7\xd2\xa6\x98\xee\x2d\x1e\xd1\xff\xed\x46\xfd\x4c\x3b\x9f\x38\xa8\xa5\x57") },
    { asBlob("And this textual data, astonishing as it may"
             " appear, is exactly 128 bytes in length, as "
             "are both SHA-384 and SHA-512 block sizes"),    asBlob("\xe3\xe3\x60\x2f\x4d\x90\xc9\x35\x32\x1d\x78\x8f\x72\x20\x71\xa8\x80\x9f\x4f\x09\x36\x6f\x28\x25"
                                                                    "\xcd\x85\xda\x97\xcc\xd2\x95\x5e\xb6\xb8\x24\x59\x74\x40\x2a\xa6\x47\x89\xed\x45\x29\x3e\x94\xba") },
    { asBlob("By hashing data that is one byte less than a"
             " multiple of a hash block length (like this "
             "127-byte string), bugs may be revealed."),     asBlob("\x1c\xa6\x50\xf3\x84\x80\xfa\x9d\xfb\x57\x29\x63\x6b\xec\x4a\x93\x5e\xbc\x1c\xd4\xc0\x05\x5e\xe5"
                                                                    "\x0c\xad\x2a\xa6\x27\xe0\x66\x87\x10\x44\xfd\x8e\x6f\xdb\x80\xed\xf1\x0b\x85\xdf\x15\xba\x7a\xab") },
};

template<size_t HashBits, class InIter>
void testHash(Error& e, HashFunction * hashFunction, InIter begin, InIter end)
{
    if(ZORG_FAILURE(e))
	return;

    if(hashFunction->getHashBits() != HashBits)
    {
	ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	return;
    }

    for(InIter p = begin; p != end; ++ p)
    {
	BitBlob<HashBits> hash;
	assert(p->expectedHash.dataSize == hash.maxSize);

	hashFunction->hash(e, p->data, hash);

	if(ZORG_FAILURE(e))
	    return;

	if(hash.dataSize != hash.maxSize)
	{
	    ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	    return;
	}

	if(memcmp(hash.buffer, p->expectedHash.buffer, p->expectedHash.dataSize) != 0)
	{
	    ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	    return;
	}
    }
}

struct MACTestVector
{
    Blob key;
    Blob data;
    Blob expectedMAC;
};

static const MACTestVector HMACSHA256TestVectors[] =
{
    // source: RFC 4231
    { asBlob("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
             "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"), asBlob("Hi There"),                                 asBlob("\xb0\x34\x4c\x61\xd8\xdb\x38\x53"
														     "\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b"
                                                                                                                     "\x88\x1d\xc2\x00\xc9\x83\x3d\xa7"
														     "\x26\xe9\x37\x6c\x2e\x32\xcf\xf7") },

    { asBlob("Jefe"),                                     asBlob("what do ya want for nothing?"),             asBlob("\x5b\xdc\xc1\x46\xbf\x60\x75\x4e"
                                                                                                                     "\x6a\x04\x24\x26\x08\x95\x75\xc7"
                                                                                                                     "\x5a\x00\x3f\x08\x9d\x27\x39\x83"
														     "\x9d\xec\x58\xb9\x64\xec\x38\x43") },

    { asBlob("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"), asBlob("\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                                                                 "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                                                                 "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                                                                 "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                                                                 "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"), asBlob("\x77\x3e\xa9\x1e\x36\x80\x0e\x46"
								                                                     "\x85\x4d\xb8\xeb\xd0\x91\x81\xa7"
                                                                                                                     "\x29\x59\x09\x8b\x3e\xf8\xc1\x22"
														     "\xd9\x63\x55\x14\xce\xd5\x65\xfe") },

    { asBlob("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
             "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
             "\x15\x16\x17\x18\x19"),                     asBlob("\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                                                                 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                                                                 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                                                                 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                                                                 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"), asBlob("\x82\x55\x8a\x38\x9a\x44\x3c\x0e"
								                                                     "\xa4\xcc\x81\x98\x99\xf2\x08\x3a"
                                                                                                                     "\x85\xf0\xfa\xa3\xe5\x78\xf8\x07"
														     "\x7a\x2e\x3f\xf4\x67\x29\x66\x5b") },

    { asBlob("\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
             "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"), asBlob("Test With Truncation"),                     asBlob("\xa3\xb6\x16\x74\x73\x10\x0e\xe0"
	                                                                                                             "\x6e\x0c\x79\x6c\x29\x55\x55\x2b") },

    { asBlob("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa"),                                     asBlob("Test Using Larger Than Block-Size Key - "
                                                                 "Hash Key First"),                           asBlob("\x60\xe4\x31\x59\x1e\xe0\xb6\x7f"
								                                                     "\x0d\x8a\x26\xaa\xcb\xf5\xb7\x7f"
                                                                                                                     "\x8e\x0b\xc6\x21\x37\x28\xc5\x14"
														     "\x05\x46\x04\x0f\x0e\xe3\x7f\x54") },

    { asBlob("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa"),                                     asBlob("This is a test using a larger than block"
                                                                 "-size key and a larger than block-size d"
                                                                 "ata. The key needs to be hashed before b"
                                                                 "eing used by the HMAC algorithm."),         asBlob("\x9b\x09\xff\xa7\x1b\x94\x2f\xcb"
								                                                     "\x27\x63\x5f\xbc\xd5\xb0\xe9\x44"
                                                                                                                     "\xbf\xdc\x63\x64\x4f\x07\x13\x93"
														     "\x8a\x7f\x51\x53\x5c\x3a\x35\xe2") },
};

static const MACTestVector HMACSHA384TestVectors[] =
{
    // source: RFC 4231
    { asBlob("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
             "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"), asBlob("Hi There"),                                 asBlob("\xaf\xd0\x39\x44\xd8\x48\x95\x62"
                                                                                                                     "\x6b\x08\x25\xf4\xab\x46\x90\x7f"
                                                                                                                     "\x15\xf9\xda\xdb\xe4\x10\x1e\xc6"
                                                                                                                     "\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c"
                                                                                                                     "\xfa\xea\x9e\xa9\x07\x6e\xde\x7f"
                                                                                                                     "\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6") },

    { asBlob("Jefe"),                                     asBlob("what do ya want for nothing?"),             asBlob("\xaf\x45\xd2\xe3\x76\x48\x40\x31"
                                                                                                                     "\x61\x7f\x78\xd2\xb5\x8a\x6b\x1b"
                                                                                                                     "\x9c\x7e\xf4\x64\xf5\xa0\x1b\x47"
                                                                                                                     "\xe4\x2e\xc3\x73\x63\x22\x44\x5e"
                                                                                                                     "\x8e\x22\x40\xca\x5e\x69\xe2\xc7"
                                                                                                                     "\x8b\x32\x39\xec\xfa\xb2\x16\x49") },

    { asBlob("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"), asBlob("\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                                                                 "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                                                                 "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                                                                 "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                                                                 "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"), asBlob("\x88\x06\x26\x08\xd3\xe6\xad\x8a"
                                                                                                                     "\x0a\xa2\xac\xe0\x14\xc8\xa8\x6f"
                                                                                                                     "\x0a\xa6\x35\xd9\x47\xac\x9f\xeb"
                                                                                                                     "\xe8\x3e\xf4\xe5\x59\x66\x14\x4b"
                                                                                                                     "\x2a\x5a\xb3\x9d\xc1\x38\x14\xb9"
                                                                                                                     "\x4e\x3a\xb6\xe1\x01\xa3\x4f\x27") },

    { asBlob("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
             "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
             "\x15\x16\x17\x18\x19"),                     asBlob("\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                                                                 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                                                                 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                                                                 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                                                                 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"), asBlob("\x3e\x8a\x69\xb7\x78\x3c\x25\x85"
                                                                                                                     "\x19\x33\xab\x62\x90\xaf\x6c\xa7"
                                                                                                                     "\x7a\x99\x81\x48\x08\x50\x00\x9c"
                                                                                                                     "\xc5\x57\x7c\x6e\x1f\x57\x3b\x4e"
                                                                                                                     "\x68\x01\xdd\x23\xc4\xa7\xd6\x79"
                                                                                                                     "\xcc\xf8\xa3\x86\xc6\x74\xcf\xfb") },

    { asBlob("\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
             "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"), asBlob("Test With Truncation"),                     asBlob("\x3a\xbf\x34\xc3\x50\x3b\x2a\x23"
                                                                                                                     "\xa4\x6e\xfc\x61\x9b\xae\xf8\x97") },

    { asBlob("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa"),                                     asBlob("Test Using Larger Than Block-Size Key - "
                                                                 "Hash Key First"),                           asBlob("\x4e\xce\x08\x44\x85\x81\x3e\x90"
                                                                                                                     "\x88\xd2\xc6\x3a\x04\x1b\xc5\xb4"
                                                                                                                     "\x4f\x9e\xf1\x01\x2a\x2b\x58\x8f"
                                                                                                                     "\x3c\xd1\x1f\x05\x03\x3a\xc4\xc6"
                                                                                                                     "\x0c\x2e\xf6\xab\x40\x30\xfe\x82"
                                                                                                                     "\x96\x24\x8d\xf1\x63\xf4\x49\x52") },

    { asBlob("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa"),                                     asBlob("This is a test using a larger than block"
                                                                 "-size key and a larger than block-size d"
                                                                 "ata. The key needs to be hashed before b"
                                                                 "eing used by the HMAC algorithm."),         asBlob("\x66\x17\x17\x8e\x94\x1f\x02\x0d"
                                                                                                                     "\x35\x1e\x2f\x25\x4e\x8f\xd3\x2c"
                                                                                                                     "\x60\x24\x20\xfe\xb0\xb8\xfb\x9a"
                                                                                                                     "\xdc\xce\xbb\x82\x46\x1e\x99\xc5"
                                                                                                                     "\xa6\x78\xcc\x31\xe7\x99\x17\x6d"
                                                                                                                     "\x38\x60\xe6\x11\x0c\x46\x52\x3e") },
};

template<size_t MACBits, class InIter>
void testMAC(Error& e, HashFunction * hashFunction, InIter begin, InIter end)
{
    if(ZORG_FAILURE(e))
	return;

    if(hashFunction->getHashBits() != MACBits)
    {
	ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	return;
    }

    for(InIter p = begin; p != end; ++ p)
    {
	BitBlob<MACBits> mac;
	assert(p->expectedMAC.dataSize <= mac.maxSize);

	hashFunction->mac(e, p->key, p->data, mac);

	if(ZORG_FAILURE(e))
	    return;

	if(mac.dataSize != mac.maxSize)
	{
	    ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	    return;
	}

	if(memcmp(mac.buffer, p->expectedMAC.buffer, p->expectedMAC.dataSize) != 0)
	{
	    ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	    return;
	}
    }
}

}

void HashFunction::selfTestSHA256(Error& e)
{
    testHash<256>(e, this, arrayBegin(SHA256TestVectors), arrayEnd(SHA256TestVectors));
    testMAC<256>(e, this, arrayBegin(HMACSHA256TestVectors), arrayEnd(HMACSHA256TestVectors));
}

void HashFunction::selfTestSHA384(Error& e)
{
    testHash<384>(e, this, arrayBegin(SHA384TestVectors), arrayEnd(SHA384TestVectors));
    testMAC<384>(e, this, arrayBegin(HMACSHA384TestVectors), arrayEnd(HMACSHA384TestVectors));
}

namespace
{

struct CFBTestVector
{
    Blob key;
    Blob iv;
    Blob data;
    Blob expectedCipher;
};

static const CFBTestVector AES128CFBTestVectors[] =
{
    // source: OpenSSL 1.0.0a, crypto/evp/evptests.txt
    { asBlob("\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"), asBlob("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"), asBlob("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"), asBlob("\x3b\x3f\xd9\x2e\xb7\x2d\xad\x20\x33\x34\x49\xf8\xe8\x3c\xfb\x4a") },
    { asBlob("\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"), asBlob("\x3B\x3F\xD9\x2E\xB7\x2D\xAD\x20\x33\x34\x49\xF8\xE8\x3C\xFB\x4A"), asBlob("\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"), asBlob("\xc8\xa6\x45\x37\xa0\xb3\xa9\x3f\xcd\xe3\xcd\xad\x9f\x1c\xe5\x8b") },
    { asBlob("\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"), asBlob("\xC8\xA6\x45\x37\xA0\xB3\xA9\x3F\xCD\xE3\xCD\xAD\x9F\x1C\xE5\x8B"), asBlob("\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"), asBlob("\x26\x75\x1f\x67\xa3\xcb\xb1\x40\xb1\x80\x8c\xf1\x87\xa4\xf4\xdf") },
    { asBlob("\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"), asBlob("\x26\x75\x1F\x67\xA3\xCB\xB1\x40\xB1\x80\x8C\xF1\x87\xA4\xF4\xDF"), asBlob("\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10"), asBlob("\xc0\x4b\x05\x35\x7c\x5d\x1c\x0e\xea\xc4\xc6\x6f\x9f\xf7\xf2\xe6") },
};

static const CFBTestVector AES192CFBTestVectors[] =
{
    // source: OpenSSL 1.0.0a, crypto/evp/evptests.txt
    { asBlob("\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b"), asBlob("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"), asBlob("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"), asBlob("\xcd\xc8\x0d\x6f\xdd\xf1\x8c\xab\x34\xc2\x59\x09\xc9\x9a\x41\x74") },
    { asBlob("\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b"), asBlob("\xCD\xC8\x0D\x6F\xDD\xF1\x8C\xAB\x34\xC2\x59\x09\xC9\x9A\x41\x74"), asBlob("\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"), asBlob("\x67\xce\x7f\x7f\x81\x17\x36\x21\x96\x1a\x2b\x70\x17\x1d\x3d\x7a") },
    { asBlob("\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b"), asBlob("\x67\xCE\x7F\x7F\x81\x17\x36\x21\x96\x1A\x2B\x70\x17\x1D\x3D\x7A"), asBlob("\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"), asBlob("\x2e\x1e\x8a\x1d\xd5\x9b\x88\xb1\xc8\xe6\x0f\xed\x1e\xfa\xc4\xc9") },
    { asBlob("\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b"), asBlob("\x2E\x1E\x8A\x1D\xD5\x9B\x88\xB1\xC8\xE6\x0F\xED\x1E\xFA\xC4\xC9"), asBlob("\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10"), asBlob("\xc0\x5f\x9f\x9c\xa9\x83\x4f\xa0\x42\xae\x8f\xba\x58\x4b\x09\xff") },
};

static const CFBTestVector AES256CFBTestVectors[] =
{
    // source: OpenSSL 1.0.0a, crypto/evp/evptests.txt
    { asBlob("\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4"), asBlob("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"), asBlob("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"), asBlob("\xdc\x7e\x84\xbf\xda\x79\x16\x4b\x7e\xcd\x84\x86\x98\x5d\x38\x60") },
    { asBlob("\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4"), asBlob("\xDC\x7E\x84\xBF\xDA\x79\x16\x4B\x7E\xCD\x84\x86\x98\x5D\x38\x60"), asBlob("\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"), asBlob("\x39\xff\xed\x14\x3b\x28\xb1\xc8\x32\x11\x3c\x63\x31\xe5\x40\x7b") },
    { asBlob("\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4"), asBlob("\x39\xFF\xED\x14\x3B\x28\xB1\xC8\x32\x11\x3C\x63\x31\xE5\x40\x7B"), asBlob("\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"), asBlob("\xdf\x10\x13\x24\x15\xe5\x4b\x92\xa1\x3e\xd0\xa8\x26\x7a\xe2\xf9") },
    { asBlob("\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4"), asBlob("\xDF\x10\x13\x24\x15\xE5\x4B\x92\xA1\x3E\xD0\xA8\x26\x7A\xE2\xF9"), asBlob("\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10"), asBlob("\x75\xa3\x85\x74\x1a\xb9\xce\xf8\x20\x31\x62\x3d\x55\xb1\xe4\x71") },
};

template<size_t KeyBits, size_t CFBIVBits, size_t BlockBits>
void testCFBCipher(Error& e, Cipher * cipher, const Blob& key, const Blob& iv, const Blob& input, const Blob& expectedOutput)
{
    if(ZORG_FAILURE(e))
	return;

    assert(key.dataSize == TemplateHell::RoundUpBitsToBytes<KeyBits>::value);
    assert(iv.dataSize == TemplateHell::RoundUpBitsToBytes<CFBIVBits>::value);
    assert(input.dataSize == expectedOutput.dataSize);

    if(cipher->getBlockBits() != BlockBits)
    {
	ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	return;
    }

    BlockIterator beginInput(beginDataBlock(input, BlockBits));
    BlockIterator endInput(endDataBlock(input, BlockBits));
    BlockIterator pExpectedOutput(beginDataBlock(expectedOutput, BlockBits));

    for(BlockIterator p = beginInput; p != endInput; ++ p, ++ pExpectedOutput)
    {
	assert(p->dataSize == pExpectedOutput->dataSize);

	BitBlob<BlockBits> outputBlock;
	cipher->processBlock(e, *p, outputBlock);

	if(ZORG_FAILURE(e))
	    return;

	if(outputBlock.dataSize != p->dataSize)
	{
	    ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	    return;
	}

	if(memcmp(outputBlock.buffer, pExpectedOutput->buffer, outputBlock.dataSize) != 0)
	{
	    ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	    return;
	}
    }
}

template<size_t KeyBits, size_t CFBIVBits, size_t BlockBits, class InIter>
void testCFBCipher(Error& e, CipherFunction * cipherFunction, InIter begin, InIter end)
{
    if(ZORG_FAILURE(e))
	return;

    if(cipherFunction->getBlockBits() != BlockBits || cipherFunction->getKeyBits() != KeyBits || cipherFunction->getCFBIVBits() != CFBIVBits)
    {
	ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	return;
    }

    for(InIter p = begin; p != end; ++ p)
    {
	testCFBCipher<KeyBits, CFBIVBits, BlockBits>(e, std::auto_ptr<Cipher>(cipherFunction->CreateEncryptorCFB(e, p->key, p->iv)).get(), p->key, p->iv, p->data, p->expectedCipher);
	testCFBCipher<KeyBits, CFBIVBits, BlockBits>(e, std::auto_ptr<Cipher>(cipherFunction->CreateDecryptorCFB(e, p->key, p->iv)).get(), p->key, p->iv, p->expectedCipher, p->data);

	if(ZORG_FAILURE(e))
	    return;
    }
}

}

void CipherFunction::selfTestAES128CFB(Error& e)
{
    testCFBCipher<128, 128, 128>(e, this, arrayBegin(AES128CFBTestVectors), arrayEnd(AES128CFBTestVectors));
}

void CipherFunction::selfTestAES192CFB(Error& e)
{
    testCFBCipher<192, 128, 128>(e, this, arrayBegin(AES192CFBTestVectors), arrayEnd(AES192CFBTestVectors));
}

void CipherFunction::selfTestAES256CFB(Error& e)
{
    testCFBCipher<256, 128, 128>(e, this, arrayBegin(AES256CFBTestVectors), arrayEnd(AES256CFBTestVectors));
}

namespace
{

struct KeyExchangeTestVector
{
    Blob secretKeyA;
    Blob publicKeyA;
    Blob secretKeyB;
    Blob publicKeyB;
    Blob sharedSecret;
};

static const KeyExchangeTestVector ECP256TestVectors[] =
{
    // source: RFC 5114
    {
	asBlob("\x81\x42\x64\x14\x5F\x2F\x56\xF2\xE9\x6A\x8E\x33\x7A\x12\x84\x99\x3F\xAF\x43\x2A\x5A\xBC\xE5\x9E\x86\x7B\x72\x91\xD5\x07\xA3\xAF"),
	asBlob("\x2A\xF5\x02\xF3\xBE\x89\x52\xF2\xC9\xB5\xA8\xD4\x16\x0D\x09\xE9\x71\x65\xBE\x50\xBC\x42\xAE\x4A\x5E\x8D\x3B\x4B\xA8\x3A\xEB\x15"
	       "\xEB\x0F\xAF\x4C\xA9\x86\xC4\xD3\x86\x81\xA0\xF9\x87\x2D\x79\xD5\x67\x95\xBD\x4B\xFF\x6E\x6D\xE3\xC0\xF5\x01\x5E\xCE\x5E\xFD\x85"),
	asBlob("\x2C\xE1\x78\x8E\xC1\x97\xE0\x96\xDB\x95\xA2\x00\xCC\x0A\xB2\x6A\x19\xCE\x6B\xCC\xAD\x56\x2B\x8E\xEE\x1B\x59\x37\x61\xCF\x7F\x41"),
	asBlob("\xB1\x20\xDE\x4A\xA3\x64\x92\x79\x53\x46\xE8\xDE\x6C\x2C\x86\x46\xAE\x06\xAA\xEA\x27\x9F\xA7\x75\xB3\xAB\x07\x15\xF6\xCE\x51\xB0"
	       "\x9F\x1B\x7E\xEC\xE2\x0D\x7B\x5E\xD8\xEC\x68\x5F\xA3\xF0\x71\xD8\x37\x27\x02\x70\x92\xA8\x41\x13\x85\xC3\x4D\xDE\x57\x08\xB2\xB6"),
	asBlob("\xDD\x0F\x53\x96\x21\x9D\x1E\xA3\x93\x31\x04\x12\xD1\x9A\x08\xF1\xF5\x81\x1E\x9D\xC8\xEC\x8E\xEA\x7F\x80\xD2\x1C\x82\x0C\x27\x88")
    },
};

static const KeyExchangeTestVector ECP384TestVectors[] =
{
    // source: RFC 5114
    {
	asBlob("\xD2\x73\x35\xEA\x71\x66\x4A\xF2\x44\xDD\x14\xE9\xFD\x12\x60\x71\x5D\xFD\x8A\x79\x65\x57\x1C\x48\xD7\x09\xEE\x7A\x79\x62\xA1\x56"
	       "\xD7\x06\xA9\x0C\xBC\xB5\xDF\x29\x86\xF0\x5F\xEA\xDB\x93\x76\xF1"),
	asBlob("\x79\x31\x48\xF1\x78\x76\x34\xD5\xDA\x4C\x6D\x90\x74\x41\x7D\x05\xE0\x57\xAB\x62\xF8\x20\x54\xD1\x0E\xE6\xB0\x40\x3D\x62\x79\x54"
	       "\x7E\x6A\x8E\xA9\xD1\xFD\x77\x42\x7D\x01\x6F\xE2\x7A\x8B\x8C\x66\xC6\xC4\x12\x94\x33\x1D\x23\xE6\xF4\x80\xF4\xFB\x4C\xD4\x05\x04"
	       "\xC9\x47\x39\x2E\x94\xF4\xC3\xF0\x6B\x8F\x39\x8B\xB2\x9E\x42\x36\x8F\x7A\x68\x59\x23\xDE\x3B\x67\xBA\xCE\xD2\x14\xA1\xA1\xD1\x28"),
	asBlob("\x52\xD1\x79\x1F\xDB\x4B\x70\xF8\x9C\x0F\x00\xD4\x56\xC2\xF7\x02\x3B\x61\x25\x26\x2C\x36\xA7\xDF\x1F\x80\x23\x11\x21\xCC\xE3\xD3"
	       "\x9B\xE5\x2E\x00\xC1\x94\xA4\x13\x2C\x4A\x6C\x76\x8B\xCD\x94\xD2"),
	asBlob("\x5C\xD4\x2A\xB9\xC4\x1B\x53\x47\xF7\x4B\x8D\x4E\xFB\x70\x8B\x3D\x5B\x36\xDB\x65\x91\x53\x59\xB4\x4A\xBC\x17\x64\x7B\x6B\x99\x99"
	       "\x78\x9D\x72\xA8\x48\x65\xAE\x2F\x22\x3F\x12\xB5\xA1\xAB\xC1\x20\xE1\x71\x45\x8F\xEA\xA9\x39\xAA\xA3\xA8\xBF\xAC\x46\xB4\x04\xBD"
	       "\x8F\x6D\x5B\x34\x8C\x0F\xA4\xD8\x0C\xEC\xA1\x63\x56\xCA\x93\x32\x40\xBD\xE8\x72\x34\x15\xA8\xEC\xE0\x35\xB0\xED\xF3\x67\x55\xDE"),
	asBlob("\x5E\xA1\xFC\x4A\xF7\x25\x6D\x20\x55\x98\x1B\x11\x05\x75\xE0\xA8\xCA\xE5\x31\x60\x13\x7D\x90\x4C\x59\xD9\x26\xEB\x1B\x84\x56\xE4"
	       "\x27\xAA\x8A\x45\x40\x88\x4C\x37\xDE\x15\x9A\x58\x02\x8A\xBC\x0E")
    },
};

static const KeyExchangeTestVector ECP521TestVectors[] =
{
    // source: RFC 5114
    {
	asBlob("\x01\x13\xF8\x2D\xA8\x25\x73\x5E\x3D\x97\x27\x66\x83\xB2\xB7\x42\x77\xBA\xD2\x73\x35\xEA\x71\x66\x4A\xF2\x43\x0C\xC4\xF3\x34\x59"
	       "\xB9\x66\x9E\xE7\x8B\x3F\xFB\x9B\x86\x83\x01\x5D\x34\x4D\xCB\xFE\xF6\xFB\x9A\xF4\xC6\xC4\x70\xBE\x25\x45\x16\xCD\x3C\x1A\x1F\xB4"
	       "\x73\x62"),
	asBlob("\x01\xEB\xB3\x4D\xD7\x57\x21\xAB\xF8\xAD\xC9\xDB\xED\x17\x88\x9C\xBB\x97\x65\xD9\x0A\x7C\x60\xF2\xCE\xF0\x07\xBB\x0F\x2B\x26\xE1"
	       "\x48\x81\xFD\x44\x42\xE6\x89\xD6\x1C\xB2\xDD\x04\x6E\xE3\x0E\x3F\xFD\x20\xF9\xA4\x5B\xBD\xF6\x41\x3D\x58\x3A\x2D\xBF\x59\x92\x4F"
	       "\xD3\x5C\x00\xF6\xB6\x32\xD1\x94\xC0\x38\x8E\x22\xD8\x43\x7E\x55\x8C\x55\x2A\xE1\x95\xAD\xFD\x15\x3F\x92\xD7\x49\x08\x35\x1B\x2F"
	       "\x8C\x4E\xDA\x94\xED\xB0\x91\x6D\x1B\x53\xC0\x20\xB5\xEE\xCA\xED\x1A\x5F\xC3\x8A\x23\x3E\x48\x30\x58\x7B\xB2\xEE\x34\x89\xB3\xB4"
	       "\x2A\x5A\x86\xA4"),
	asBlob("\x00\xCE\xE3\x48\x0D\x86\x45\xA1\x7D\x24\x9F\x27\x76\xD2\x8B\xAE\x61\x69\x52\xD1\x79\x1F\xDB\x4B\x70\xF7\xC3\x37\x87\x32\xAA\x1B"
	       "\x22\x92\x84\x48\xBC\xD1\xDC\x24\x96\xD4\x35\xB0\x10\x48\x06\x6E\xBE\x4F\x72\x90\x3C\x36\x1B\x1A\x9D\xC1\x19\x3D\xC2\xC9\xD0\x89"
	       "\x1B\x96"),
	asBlob("\x01\x0E\xBF\xAF\xC6\xE8\x5E\x08\xD2\x4B\xFF\xFC\xC1\xA4\x51\x1D\xB0\xE6\x34\xBE\xEB\x1B\x6D\xEC\x8C\x59\x39\xAE\x44\x76\x62\x01"
	       "\xAF\x62\x00\x43\x0B\xA9\x7C\x8A\xC6\xA0\xE9\xF0\x8B\x33\xCE\x7E\x9F\xEE\xB5\xBA\x4E\xE5\xE0\xD8\x15\x10\xC2\x42\x95\xB8\xA0\x8D"
	       "\x02\x35\x00\xA4\xA6\xEC\x30\x0D\xF9\xE2\x57\xB0\x37\x2B\x5E\x7A\xBF\xEF\x09\x34\x36\x71\x9A\x77\x88\x7E\xBB\x0B\x18\xCF\x80\x99"
	       "\xB9\xF4\x21\x2B\x6E\x30\xA1\x41\x9C\x18\xE0\x29\xD3\x68\x63\xCC\x9D\x44\x8F\x4D\xBA\x4D\x2A\x0E\x60\x71\x1B\xE5\x72\x91\x5F\xBD"
	       "\x4F\xEF\x26\x95"),
	asBlob("\x00\xCD\xEA\x89\x62\x1C\xFA\x46\xB1\x32\xF9\xE4\xCF\xE2\x26\x1C\xDE\x2D\x43\x68\xEB\x56\x56\x63\x4C\x7C\xC9\x8C\x7A\x00\xCD\xE5"
	       "\x4E\xD1\x86\x6A\x0D\xD3\xE6\x12\x6C\x9D\x2F\x84\x5D\xAF\xF8\x2C\xEB\x1D\xA0\x8F\x5D\x87\x52\x1B\xB0\xEB\xEC\xA7\x79\x11\x16\x9C"
	       "\x20\xCC")
    },
};

template<size_t SecretKeyBits, size_t PublicKeyBits, size_t SharedSecretBits, class InIter>
void testKeyExchange(Error& e, KeyExchangeFunction * keyExchangeFunction, InIter begin, InIter end)
{
    if(ZORG_FAILURE(e))
	return;

    if(keyExchangeFunction->getPrivateKeyBits() != SecretKeyBits || keyExchangeFunction->getPublicKeyBits() != PublicKeyBits || keyExchangeFunction->getSharedSecretBits() != SharedSecretBits)
    {
	ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	return;
    }

    for(InIter p = begin; p != end; ++ p)
    {
	std::auto_ptr<KeyExchange> keyExchangeA(keyExchangeFunction->Create(e, p->secretKeyA));
	std::auto_ptr<KeyExchange> keyExchangeB(keyExchangeFunction->Create(e, p->secretKeyB));

	if(ZORG_FAILURE(e))
	    return;

	if(compareData(keyExchangeA->getPublicKey(e, BitBlob<PublicKeyBits>()), p->publicKeyA) != 0)
	{
	    ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	    return;
	}

	if(compareData(keyExchangeB->getPublicKey(e, BitBlob<PublicKeyBits>()), p->publicKeyB) != 0)
	{
	    ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	    return;
	}

	if(compareData(keyExchangeA->agree(e, p->publicKeyB, BitBlob<SharedSecretBits>()), p->sharedSecret) != 0)
	{
	    ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	    return;
	}

	if(compareData(keyExchangeB->agree(e, p->publicKeyA, BitBlob<SharedSecretBits>()), p->sharedSecret) != 0)
	{
	    ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	    return;
	}
    }
}

}

void KeyExchangeFunction::selfTestECP256(Error& e)
{
    testKeyExchange<256, 512, 256>(e, this, arrayBegin(ECP256TestVectors), arrayEnd(ECP256TestVectors));
}

void KeyExchangeFunction::selfTestECP384(Error& e)
{
    testKeyExchange<384, 768, 384>(e, this, arrayBegin(ECP384TestVectors), arrayEnd(ECP384TestVectors));
}

void KeyExchangeFunction::selfTestECP521(Error& e)
{
    testKeyExchange<521, 1056, 521>(e, this, arrayBegin(ECP521TestVectors), arrayEnd(ECP521TestVectors));
}

// EOF
