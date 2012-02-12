package zorg.platform.j2se;

import zorg.platform.AddressBook;
import zorg.platform.CryptoUtils;
import zorg.platform.PersistentHashtable;
import zorg.platform.Utils;
import zorg.platform.ZrtpLogger;

public class PlatformImpl implements zorg.platform.Platform {
	
	ZrtpLogger logger = new StandardLoggerImpl();
	Utils utils = new UtilsImpl();
	CryptoUtils cryptoUtils = new CryptoUtilsImpl();
	
	public PlatformImpl() {
		
	}

	@Override
	public ZrtpLogger getLogger() {
		return logger;
	}

	@Override
	public AddressBook getAddressBook() {
		// TODO Auto-generated method stub
		throw new RuntimeException("not implemented");
	}

	@Override
	public CryptoUtils getCrypto() {
		return cryptoUtils;
	}

	@Override
	public Utils getUtils() {
		return utils;
	}

	@Override
	public boolean isDebugVersion() {
		return true;  // FIXME
	}

	@Override
	public PersistentHashtable getHashtable() {
		// TODO Auto-generated method stub
		throw new RuntimeException("not implemented");
	}

}
