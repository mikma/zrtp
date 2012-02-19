package org.opentelecoms.media.rtp.secure.platform.j2se;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;

import org.opentelecoms.media.rtp.secure.ZrtpCacheEntry;
import org.opentelecoms.media.rtp.secure.platform.PersistentHashtable;


public class PersistentHashtableImpl extends HashMap<String, ZrtpCacheEntry> implements
		PersistentHashtable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	public PersistentHashtableImpl() {
		
	}
	
	@Override
	public void remove(String zid) {
		super.remove(zid);
	}

	@Override
	public void put(String zid, byte[] data, String phoneNumber) {
		super.put(zid, new ZrtpCacheEntryImpl(data, phoneNumber));
	}

	@Override
	public Enumeration<String> keys() {
		return Collections.enumeration(keySet());
	}

	@Override
	public ZrtpCacheEntry get(String zid) {
		return super.get(zid);
	}

	@Override
	public void reset() {
		super.clear();
	}


}
