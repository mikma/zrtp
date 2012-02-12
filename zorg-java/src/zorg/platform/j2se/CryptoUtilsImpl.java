package zorg.platform.j2se;

import zorg.CryptoException;
import zorg.platform.DiffieHellmanSuite;
import zorg.platform.Digest;
import zorg.platform.EncryptorSuite;
import zorg.platform.HMAC;
import zorg.platform.RandomGenerator;

public class CryptoUtilsImpl implements zorg.platform.CryptoUtils {
	
	public CryptoUtilsImpl() {
		
	}

	@Override
	public Digest createDigestSHA1() {
		// TODO Auto-generated method stub
		throw new RuntimeException("not implemented");
	}

	@Override
	public Digest createDigestSHA256() {
		// TODO Auto-generated method stub
		throw new RuntimeException("not implemented");
	}

	@Override
	public Digest createDigestSHA384() {
		// TODO Auto-generated method stub
		throw new RuntimeException("not implemented");
	}

	@Override
	public byte[] calculateSHA256HMAC(byte[] data, int offset, int length,
			byte[] aKey) {
		// TODO Auto-generated method stub
		throw new RuntimeException("not implemented");
	}

	@Override
	public byte[] calculateSHA384HMAC(byte[] data, int offset, int length,
			byte[] aKey) {
		// TODO Auto-generated method stub
		throw new RuntimeException("not implemented");
	}

	@Override
	public HMAC createHMACSHA1(byte[] hmacKey) throws CryptoException {
		return new HMACSHA1Impl(hmacKey);
	}

	@Override
	public RandomGenerator getRandomGenerator() {
		// TODO Auto-generated method stub
		throw new RuntimeException("not implemented");
	}

	@Override
	public byte[] aesEncrypt(byte[] data, byte[] key, byte[] initVector)
			throws CryptoException {
		// TODO Auto-generated method stub
		throw new RuntimeException("not implemented");
	}

	@Override
	public byte[] aesDecrypt(byte[] data, int offset, int length, byte[] key,
			byte[] initVector) throws CryptoException {
		// TODO Auto-generated method stub
		throw new RuntimeException("not implemented");
	}

	@Override
	public DiffieHellmanSuite createDHSuite() {
		// TODO Auto-generated method stub
		throw new RuntimeException("not implemented");
	}

	@Override
	public EncryptorSuite createEncryptorSuite(byte[] key, byte[] initVector)
			throws CryptoException {
		return new EncryptorSuiteImpl(key, initVector);
	}

}
