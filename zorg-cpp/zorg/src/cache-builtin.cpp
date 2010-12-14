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

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include <algorithm>
#include <functional>
#include <iterator>
#include <memory>
#include <limits>

#include <zorg/zorg.h>
#include <zorg/zrtp.h>
#include <zorg/crypto.h>
#include <zorg/log.h>
#include <zorg/snprintf.h>

using namespace ::ZORG;
using namespace ::ZORG::ZRTP;
using namespace ::ZORG::Crypto;

using ZORG::Impl::zorg_snprintf;

namespace
{
static const char LOGC[] = "cache-builtin.cpp";
static const size_t LOGGING_CONTEXT_SIZE = 16 + 1;
}

typedef Blnum<ZID_BITS * 2> CacheKey;

CacheKey makeKey(const ZID& zid1, const ZID& zid2)
{
    CacheKey ret;

    if(zid1 <= zid2)
    {
	memcpy(&ret.bytes[0], &zid1.bytes[0], zid1.BYTES);
	memcpy(&ret.bytes[zid1.BYTES], &zid2.bytes[0], zid2.BYTES);
    }
    else
    {
	memcpy(&ret.bytes[0], &zid2.bytes[0], zid2.BYTES);
	memcpy(&ret.bytes[zid2.BYTES], &zid1.bytes[0], zid1.BYTES);
    }

    return ret;
}

typedef uint64_t CacheEntryExpiration;
typedef uint32_t CacheEntryTTL;

CacheEntryExpiration expirationNow()
{
    // FIXME: watch for 32-bit time_t (2038 issue)
    time_t now;
    return static_cast<CacheEntryExpiration>(time(&now));
}

CacheEntryExpiration toExpiration(CacheEntryTTL ttl)
{
    if(ttl == 0xffffffff)
	return ~CacheEntryExpiration(0);
    else if(ttl == 0)
	return CacheEntryExpiration(0);
    else
	// FIXME: watch for overflow
	return expirationNow() + ttl;
}

struct CookedCacheEntry
{
    CacheKey key;
    BitBlob<RS_BITS> rs1;
    BitBlob<RS_BITS> rs2;
    CacheEntryExpiration expirationTime;
    bool sasVerified;
};

enum CacheEntryFlags
{
    CacheEntryValidRS1,
    CacheEntryValidRS2,
    CacheEntrySASVerified,
};

struct RawCacheEntry
{
    CacheKey key;
    BitArray<RS_BITS> rs1;
    BitArray<RS_BITS> rs2;
    BitArray<64> expirationTime;
    uint8_t flags;
};

void formatCacheEntry(::ZORG::Error& e, const CookedCacheEntry& cookedCacheEntry, RawCacheEntry& rawCacheEntry)
{
    if(ZORG_FAILURE(e))
	return;

    rawCacheEntry.key = cookedCacheEntry.key;

    if(cookedCacheEntry.rs1.dataSize)
	rawCacheEntry.rs1 = cookedCacheEntry.rs1;

    if(cookedCacheEntry.rs2.dataSize)
	rawCacheEntry.rs2 = cookedCacheEntry.rs2;

    rawCacheEntry.expirationTime = int64_BE(cookedCacheEntry.expirationTime);
    rawCacheEntry.flags = (!!cookedCacheEntry.rs1.dataSize << CacheEntryValidRS1) | (!!cookedCacheEntry.rs2.dataSize << CacheEntryValidRS2) | (!!cookedCacheEntry.sasVerified << CacheEntrySASVerified);
}

void cookCacheEntry(::ZORG::Error& e, const RawCacheEntry& rawCacheEntry, CookedCacheEntry& cookedCacheEntry)
{
    if(ZORG_FAILURE(e))
	return;

    cookedCacheEntry.key = rawCacheEntry.key;

    if(rawCacheEntry.flags & (1 << CacheEntryValidRS1))
	cookedCacheEntry.rs1 = rawCacheEntry.rs1;
    else
	cookedCacheEntry.rs1.dataSize = 0;

    if(rawCacheEntry.flags & (1 << CacheEntryValidRS2))
	cookedCacheEntry.rs2 = rawCacheEntry.rs2;
    else
	cookedCacheEntry.rs2.dataSize = 0;

    cookedCacheEntry.expirationTime = asInt64_BE(rawCacheEntry.expirationTime);
    cookedCacheEntry.sasVerified = !!(rawCacheEntry.flags & (1 << CacheEntrySASVerified));
}

struct KeyOfCacheEntry: public std::unary_function<CookedCacheEntry, CacheKey >
{
    const CacheKey& operator()(const CookedCacheEntry& X) const { return X.key; }
};

template<class T, class KeyOfPred, class Key = typename KeyOfPred::result_type, class KeyComp = std::less<Key> >
class SimpleIntrusiveSet
{
public:
    typedef T * iterator;
    typedef typename std::iterator_traits<iterator>::pointer pointer;
    typedef typename std::iterator_traits<iterator>::reference reference;
    typedef typename std::iterator_traits<iterator>::value_type value_type;
    typedef typename std::iterator_traits<iterator>::difference_type difference_type;
    typedef std::reverse_iterator<iterator> reverse_iterator;

    typedef const T * const_iterator;
    typedef typename std::iterator_traits<const_iterator>::pointer const_pointer;
    typedef typename std::iterator_traits<const_iterator>::reference const_reference;
    typedef std::reverse_iterator<const_iterator> const_reverse_iterator;

    typedef Key key_type;
    typedef KeyComp key_compare;
    typedef KeyOfPred key_of_pred;

    typedef size_t size_type;

private:
    class SearchPredicate: public std::binary_function<key_type, key_type, typename key_compare::result_type>
    {
    private:
	key_compare m_keyComp;
	key_of_pred m_keyOf;

    public:
	key_compare key_comp() const { return m_keyComp; }
	key_of_pred key_of() const { return m_keyOf; }

	typename key_compare::result_type operator()(const key_type& x, const key_type& y) const { return m_keyComp(x, y); }
	typename key_compare::result_type operator()(const value_type& x, const key_type& y) const { return (*this)(m_keyOf(x), y); }
	typename key_compare::result_type operator()(const key_type& x, const value_type& y) const { return (*this)(x, m_keyOf(y)); }
	typename key_compare::result_type operator()(const value_type& x, const value_type& y) const { return (*this)(m_keyOf(x), m_keyOf(y)); }
    };

private:
    value_type * m_array;
    size_type m_arraySize;
    size_type m_arrayMaxSize;
    const SearchPredicate m_searchPred;

    void resizeArray(::ZORG::Error& e, size_type newSize)
    {
	if(ZORG_FAILURE(e))
	    return;

	// no change: nothing to do
	if(newSize == m_arraySize)
	    return;

	// too large
	if(newSize > max_size())
	{
	    ZORG_SET_ERROR(e, ErrorNoMemory);
	    return;
	}

	// allocate the new array
	value_type * newArray = new(e) value_type[newSize];

	// couldn't allocate
	if(newArray == NULL)
	{
	    // we were trying to allocate a larger array: failure is critical
	    if(newSize > m_arrayMaxSize)
		return;
	    // otherwise, keep the current array: it's large enough
	    else
	    {
		// clear the allocation error, we don't care
		ZORG_CLEAR_ERROR(e);

		// we are erasing elements from the end of the array
		if(newSize < m_arraySize)
		{
		    // destroy and default-construct all erased elements
		    for(size_type i = newSize; i < m_arraySize; ++ i)
		    {
			m_array[i].~value_type();
			new(&m_array[i]) value_type();
		    }
		}
	    }
	}
	else
	{
	    // copy as much as possible of the old array into the new one
	    std::copy(m_array, m_array + std::min(newSize, m_arraySize), newArray);

	    // use the new array from now on
	    std::swap(m_array, newArray);
	}

	// delete the unused array (whichever it is)
	delete[] newArray;

	// set the new array size
	m_arraySize = newSize;
    }

public:
    SimpleIntrusiveSet(): m_array(), m_arraySize(), m_arrayMaxSize(), m_searchPred() {}
    ~SimpleIntrusiveSet() { delete[] m_array; }

    void swap(SimpleIntrusiveSet& Y)
    {
	std::swap(m_array, Y.m_array);
	std::swap(m_arraySize, Y.m_arraySize);
	std::swap(m_arrayMaxSize, Y.m_arrayMaxSize);
    }

    size_type max_size() const { return std::numeric_limits<size_type>::max() / sizeof(value_type); }
    size_type size() const { return m_arraySize; }
    bool empty() const { return size() == 0; }

    iterator begin() { return m_array; }
    const_iterator begin() const { return m_array; }

    iterator end() { return m_array + m_arraySize; }
    const_iterator end() const { return m_array + m_arraySize; }

    reverse_iterator rbegin() { return reverse_iterator(end()); }
    const_reverse_iterator rbegin() const { return const_reverse_iterator(end()); }

    reverse_iterator rend() { return reverse_iterator(begin()); }
    const_reverse_iterator rend() const { return const_reverse_iterator(begin()); }

    iterator erase(iterator p)
    {
	assert(p >= begin() && p < end());
	return erase(p, p + 1);
    }

    iterator erase(iterator from, iterator to)
    {
	assert(from >= begin() && from <= end());
	assert(to >= begin() && to <= end());
	assert(from <= to);

	std::copy(to, end(), from);
	difference_type i = from - begin();

	ZORG_DECL_ERROR(nonFatal);
	resizeArray(nonFatal, m_arraySize - (to - from));

	return begin() + i;
    }

    size_type erase(const key_type& X)
    {
	iterator p = find(X);

	if(p != end())
	{
	    erase(p);
	    return 1;
	}

	return 0;
    }

    iterator find(const key_type& X)
    {
	iterator p = lower_bound(X);

	if(p == end() || (!m_searchPred(*p, X) && !m_searchPred(X, *p)))
	    return p;
	else
	    return end();
    }

    const_iterator find(const key_type& X) const
    {
	const_iterator p = lower_bound(X);

	if(p == end() || (!m_searchPred(*p, X) && !m_searchPred(X, *p)))
	    return p;
	else
	    return end();
    }

    iterator lower_bound(const key_type& X)
    {
	return std::lower_bound(begin(), end(), X, m_searchPred);
    }

    const_iterator lower_bound(const key_type& X) const
    {
	return std::lower_bound(begin(), end(), X, m_searchPred);
    }

    iterator upper_bound(const key_type& X)
    {
	return std::upper_bound(begin(), end(), X, m_searchPred);
    }

    const_iterator upper_bound(const key_type& X) const
    {
	return std::upper_bound(begin(), end(), X, m_searchPred);
    }

    std::pair<iterator, bool> insert(::ZORG::Error& e, const value_type& X)
    {
	if(ZORG_FAILURE(e))
	    return std::make_pair(end(), false);

	iterator p = lower_bound(m_searchPred.key_of()(X));

	if(p != end() && !m_searchPred(*p, X) && !m_searchPred(X, *p))
	{
	    *p = X;
	    return std::make_pair(p, false);
	}

	size_type oldSize = m_arraySize;
	difference_type i = p - begin();

	resizeArray(e, m_arraySize + 1);

	if(ZORG_FAILURE(e))
	    return std::make_pair(end(), false);

	p = begin() + i;
	std::copy_backward(p, begin() + oldSize, end());

	*p = X;
	return std::make_pair(p, true);
    }

    iterator insert(::ZORG::Error& e, iterator, const value_type& X)
    {
	(void)insert(e, X);
    }

    template<class Iter>
    void insert(::ZORG::Error& e, Iter from, Iter to)
    {
	if(ZORG_FAILURE(e))
	    return;

	for(Iter p = from; !(p == to); ++ p)
	    insert(e, *p);
    }

    void clear()
    {
	(void)erase(begin(), end());
    }

    template<class Iter> void assign(::ZORG::Error& e, Iter from, Iter to)
    {
	if(ZORG_FAILURE(e))
	    return;

	clear();
	insert(e, from, to);
    }
};

class ZORGCache: public Cache
{
private:
    static FILE * openFile(::ZORG::Error& e, const char * fileName, const char * mode)
    {
	if(ZORG_FAILURE(e))
	    return NULL;

	if(fileName == NULL)
	{
	    ZORG_SET_ERROR(e, ErrorInternal);
	    return NULL;
	}

	FILE * ret = fopen(fileName, mode);

	if(ret == NULL)
	{
	    ZORG_SET_ERROR(e, ErrorInternal);
	    return NULL;
	}

	return ret;
    }

    static void closeFile(FILE * f)
    {
	if(f)
	    fclose(f);
    }

    static void writeFile(::ZORG::Error& e, const void * data, size_t size, FILE * dest)
    {
	size_t ret;

	if(ZORG_FAILURE(e))
	    return;

	if((ret = fwrite(data, size, 1, dest)) != 1)
	    ZORG_SET_ERROR(e, ErrorInternal);
    }

    static void readFile(::ZORG::Error& e, void * data, size_t size, FILE *srcf)
    {
	size_t ret;

	if(ZORG_FAILURE(e))
	    return;

	if((ret = fread(data, size, 1, srcf)) != 1)
	    ZORG_SET_ERROR(e, ErrorInternal);
    }

private:
    static char * stringDup(::ZORG::Error& e, const char * str)
    {
	if(ZORG_FAILURE(e))
	    return NULL;

	if(str == NULL)
	    return NULL;

	size_t strLen = strlen(str) + 1;
	char * strDup = new(e) char[strLen];

	if(strDup)
	    memcpy(strDup, str, strLen);

	return strDup;
    }

    static void stringFree(const char * str)
    {
	delete[] str;
    }

private:
    typedef SimpleIntrusiveSet<CookedCacheEntry, KeyOfCacheEntry> CacheHolder;

private:
    CacheHolder m_cache;
    const char * m_cacheFile;
    std::auto_ptr<Crypto::HashFunction> m_sha256;
    char LOGC[LOGGING_CONTEXT_SIZE];

private:
    void saveCache()
    {
	if(m_cacheFile == NULL)
	    return;

	ZORG_LOG(2,(LOGC, "saving cache to file \"%s\"", m_cacheFile));

	ZORG_DECL_ERROR(e);

	CacheEntryExpiration now = expirationNow();
	std::auto_ptr<Crypto::Hash> mac(m_sha256->Create(e, asBlob("zrtp.org cache")));

	if(ZORG_FAILURE(e))
	    return;

	FILE * f = openFile(e, m_cacheFile, "wb");

	unsigned saved = 0;
	unsigned expired = 0;

	for(CacheHolder::const_iterator p = m_cache.begin(); !(p == m_cache.end()); ++ p)
	{
	    if(p->expirationTime > now)
	    {
		RawCacheEntry rawEntry;
		formatCacheEntry(e, *p, rawEntry);
		
		uint8_t marker = 1;
		writeFile(e, &marker, sizeof(marker), f);
		mac->next(e, rawObjectAsBlob(marker));

		writeFile(e, &rawEntry, sizeof(rawEntry), f);
		mac->next(e, rawObjectAsBlob(rawEntry));

		if(ZORG_SUCCESS(e))
		{
		    ZORG_LOG(3,(LOGC, "saved cache entry: <%s> = { rs1: %s, rs2: %s, V: %u }", ZORG_HEX_LINE_DUMP(p->key), ZORG_HEX_LINE_DUMP(p->rs1), ZORG_HEX_LINE_DUMP(p->rs2), !!p->sasVerified));
		    ++ saved;
		}
	    }
	    else
	    {
		ZORG_LOG(3,(LOGC, "expired cache entry not saved: <%s> (expired %d seconds ago)", ZORG_HEX_LINE_DUMP(p->key), now - p->expirationTime));
		++ expired;
	    }

	    if(ZORG_FAILURE(e))
		break;
	}

	uint8_t marker = 0;
	writeFile(e, &marker, sizeof(marker), f);
	mac->next(e, rawObjectAsBlob(marker));

	BitArray<IMPLICIT_HASH_BITS> fileMac;
	mac->finish(e, asBlob(fileMac));
	writeFile(e, &fileMac, sizeof(fileMac), f);

	closeFile(f);

	if(ZORG_SUCCESS(e))
	    ZORG_LOG(3,(LOGC, "successfully saved cache to \"%s\": %u entries saved, %u entries expired", m_cacheFile, saved, expired));
    }

    void loadCache()
    {
	if(m_cacheFile == NULL)
	    return;

	ZORG_LOG(2,(LOGC, "loading cache from file \"%s\"", m_cacheFile));

	ZORG_DECL_ERROR(e);

	CacheHolder newCache;
	CacheEntryExpiration now = expirationNow();

	FILE * f = openFile(e, m_cacheFile, "rb+");
	std::auto_ptr<Crypto::Hash> mac(m_sha256->Create(e, asBlob("zrtp.org cache")));

	unsigned loaded = 0;
	unsigned expired = 0;

	while(ZORG_SUCCESS(e))
	{
	    uint8_t marker;
	    readFile(e, &marker, sizeof(marker), f);
	    mac->next(e, rawObjectAsBlob(marker));

	    if(marker == 0)
	    {
		BitArray<IMPLICIT_HASH_BITS> actualMac;
		readFile(e, &actualMac, sizeof(actualMac), f);

		BitArray<IMPLICIT_HASH_BITS> expectedMac;
		mac->finish(e, asBlob(expectedMac));

		if(ZORG_SUCCESS(e) && actualMac != expectedMac)
		{
		    ZORG_LOG(2,(LOGC, "cache file \"%s\" corrupted", m_cacheFile));
		    ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
		}

		break;
	    }
	    else if(marker == 1)
	    {
		RawCacheEntry rawEntry;
		readFile(e, &rawEntry, sizeof(rawEntry), f);
		mac->next(e, rawObjectAsBlob(rawEntry));

		CookedCacheEntry entry;
		cookCacheEntry(e, rawEntry, entry);

		if(ZORG_SUCCESS(e))
		{
		    if(entry.expirationTime > now)
		    {
			newCache.insert(e, entry);

			if(ZORG_SUCCESS(e))
			    ++ loaded;
		    }
		    else
		    {
			ZORG_LOG(3,(LOGC, "expired cache entry not loaded: <%s> (expired %d seconds ago)", ZORG_HEX_LINE_DUMP(entry.key), now - entry.expirationTime));
			++ expired;
		    }
		}
	    }
	    else
		ZORG_SET_ERROR(e, ErrorInternal/*TODO*/);
	}

	closeFile(f);

	if(ZORG_SUCCESS(e))
	{
	    ZORG_LOG(3,(LOGC, "successfully loaded cache from \"%s\": %u entries loaded, %u entries expired", m_cacheFile, loaded, expired));

	    for(CacheHolder::const_iterator p = newCache.begin(); p != newCache.end(); ++ p)
		ZORG_LOG(3,(LOGC, "loaded cache entry: <%s> = { rs1: %s, rs2: %s, V: %u }", ZORG_HEX_LINE_DUMP(p->key), ZORG_HEX_LINE_DUMP(p->rs1), ZORG_HEX_LINE_DUMP(p->rs2), !!p->sasVerified));

	    m_cache.swap(newCache);
	}
    }

public:
    void lookupEntry(const ZID& zid1, const ZID& zid2, BitBlob<RS_BITS>& rs1, BitBlob<RS_BITS>& rs2)
    {
	CacheHolder::iterator p = m_cache.find(makeKey(zid1, zid2));

	if(p == m_cache.end())
	{
	    rs1.dataSize = 0;
	    rs2.dataSize = 0;
	}
	else if(p->expirationTime < expirationNow())
	{
	    ZORG_LOG(2,(LOGC, "entry <%s> expired", ZORG_HEX_LINE_DUMP(p->key)));
	    m_cache.erase(p);
	    rs1.dataSize = 0;
	    rs2.dataSize = 0;
	}
	else
	{
	    ZORG_LOG(3,(LOGC, "retrieved entry <%s> = { rs1: %s, rs2: %s }", ZORG_HEX_LINE_DUMP(p->key), ZORG_HEX_LINE_DUMP(p->rs1), ZORG_HEX_LINE_DUMP(p->rs2)));
	    rs1 = p->rs1;
	    rs2 = p->rs2;
	}
    }

    void updateEntry(const ZID& zid1, const ZID& zid2, const BitArray<RS_BITS>& rs1, uint32_t ttl)
    {
	CacheKey key = makeKey(zid1, zid2);
	CacheHolder::iterator p = m_cache.find(key);

	if(p == m_cache.end())
	{
	    CookedCacheEntry x = {};
	    x.key = key;
	    x.rs1 = rs1;
	    x.rs2.dataSize = 0;
	    x.expirationTime = toExpiration(ttl);

	    ZORG_DECL_ERROR(nonFatal);
	    m_cache.insert(nonFatal, x);

	    if(ZORG_SUCCESS(nonFatal))
		ZORG_LOG(3,(LOGC, "added entry <%s> = { rs1: %s, ttl: %d }", ZORG_HEX_LINE_DUMP(x.key), ZORG_HEX_LINE_DUMP(x.rs1), (int32_t)ttl));
	    else
		ZORG_LOG(2,(LOGC, "cannot cache entry <%s> = { rs1: %s, ttl: %d }", ZORG_HEX_LINE_DUMP(x.key), ZORG_HEX_LINE_DUMP(x.rs1), (int32_t)ttl));
	}
	else
	{
	    ZORG_LOG(3,(LOGC, "updated cache entry <%s> = { rs1: %s, rs2: %s, ttl: %d } -> { rs1: %s, rs2: %s, ttl: %d }", ZORG_HEX_LINE_DUMP(key), ZORG_HEX_LINE_DUMP(p->rs1), ZORG_HEX_LINE_DUMP(p->rs2), (int32_t)(p->expirationTime - expirationNow()), ZORG_HEX_LINE_DUMP(rs1), ZORG_HEX_LINE_DUMP(p->rs1), (int32_t)ttl));

	    p->rs2 = p->rs1;
	    p->rs1 = rs1;
	    p->expirationTime = toExpiration(ttl);
	}
    }

    void deleteEntry(const ZID& zid1, const ZID& zid2)
    {
	m_cache.erase(makeKey(zid1, zid2));
    }

    bool getVerified(const ZID& zid1, const ZID& zid2, bool& isVerified)
    {
	CacheHolder::iterator p = m_cache.find(makeKey(zid1, zid2));

	if(p != m_cache.end())
	    isVerified = p->sasVerified;
	else
	    ZORG_LOG(2,(LOGC, "cannot get V flag for <%s>: session not found", ZORG_HEX_LINE_DUMP(makeKey(zid1, zid2))));

	return p != m_cache.end();
    }

    bool setVerified(const ZID& zid1, const ZID& zid2, bool isVerified)
    {
	CacheHolder::iterator p = m_cache.find(makeKey(zid1, zid2));

	if(p != m_cache.end())
	{
	    ZORG_LOG(3,(LOGC, "updated cache entry <%s> = { V: %u } -> { V: %u }", ZORG_HEX_LINE_DUMP(makeKey(zid1, zid2)), !!p->sasVerified, !!isVerified));
	    p->sasVerified = isVerified;
	}
	else
	    ZORG_LOG(2,(LOGC, "cannot set V flag for <%s>: session not found", ZORG_HEX_LINE_DUMP(makeKey(zid1, zid2))));

	return p != m_cache.end();
    }

    void flush()
    {
	saveCache();
    }

    ZORGCache(::ZORG::Error& e, const char * file, CryptoSuite * cryptoSuite): m_cacheFile(stringDup(e, file))
    {
	if(ZORG_FAILURE(e))
	    return;

	static unsigned cacheId = 0;
	zorg_snprintf(LOGC, sizeof(LOGC), "zcache%u", ++ cacheId);
	LOGC[sizeof(LOGC) - 1] = 0;

	if(m_cacheFile)
	    m_sha256.reset(cryptoSuite->createHashFunction(e, HashS256));

	if(ZORG_SUCCESS(e))
	    loadCache();
    }

    virtual ~ZORGCache()
    {
	saveCache();
	stringFree(m_cacheFile);
    }
};

namespace ZORG
{
namespace ZRTP
{
namespace Impl
{

Cache * CreateCache(::ZORG::Error& e, const char * file, CryptoSuite * cryptoSuite)
{
    return guard_new(e, new(e) ZORGCache(e, file, cryptoSuite));
}

}
}
}

// EOF
