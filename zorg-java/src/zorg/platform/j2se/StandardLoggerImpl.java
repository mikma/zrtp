package zorg.platform.j2se;

import java.util.logging.Level;

import zorg.platform.ZrtpLogger;

public class StandardLoggerImpl implements ZrtpLogger {
	
	java.util.logging.Logger logger = java.util.logging.Logger.getLogger("ZRTP");

	@Override
	public boolean isEnabled() {
		return true;  // FIXME
	}

	@Override
	public void log(String message) {
		logger.log(Level.INFO, message);
	}

	@Override
	public void log(String message, byte[] buffer) {
		logger.log(Level.INFO, message + ": " + new UtilsImpl().byteToHexString(buffer));
	}

	@Override
	public void logWarning(String message) {
		logger.warning(message);
	}

	@Override
	public void logException(String message) {
		logger.log(Level.SEVERE, message);
	}

}
