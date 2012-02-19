package org.opentelecoms.media.rtp.secure.platform.j2se;

import org.opentelecoms.media.rtp.secure.platform.AddressBook;

public class AddressBookImpl implements AddressBook {

	@Override
	public boolean matchingNumbers(String number1, String number2) {
		// FIXME - use libphonenumber
		return number1.equals(number2);
	}

	@Override
	public boolean isInAddressBook(String phoneNumber) {
		// FIXME - not a real address book
		return false; 
	}

}
