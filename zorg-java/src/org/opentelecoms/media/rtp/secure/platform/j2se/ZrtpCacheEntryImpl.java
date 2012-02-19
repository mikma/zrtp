package org.opentelecoms.media.rtp.secure.platform.j2se;

import org.opentelecoms.media.rtp.secure.ZrtpCacheEntry;

public class ZrtpCacheEntryImpl implements ZrtpCacheEntry {
	
	byte[] data;
	String number;
	
	public ZrtpCacheEntryImpl(byte[] data, String number) {
		setData(data);
		setNumber(number);
	}

	@Override
	public void setData(byte[] data) {
		if(data == null) {
			this.data = null;
		} else {
			this.data = new byte[data.length];
			for(int i = 0; i < data.length; i++)
				this.data[i] = data[i];
		}
	}

	@Override
	public void setNumber(String number) {
		if(number != null)
			this.number = new String(number);
		else
			number = null;
	}

	@Override
	public byte[] getData() {
		return data;
	}

	@Override
	public String getNumber() {
		return number;
	}

}
