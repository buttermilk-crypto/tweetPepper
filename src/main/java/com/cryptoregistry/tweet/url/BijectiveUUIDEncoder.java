package com.cryptoregistry.tweet.url;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * Encode a UUID using Bijective conversion. Produces a 22 character string to encode 128 bits. This
 * is normally two characters shorter than the Base64 format, and 14 characters shorter than a nominal 
 * UUID or GUID string.
 * 
 * @author Dave
 */
public final class BijectiveUUIDEncoder {

	private final List<Integer> digits;
	private final ByteBuffer bb;

	private static final char[] ALPHABET = { '0', '1', '2', '3', '4', '5', '6',
			'7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
			'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
			'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
			'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
			'X', 'Y', 'Z'};

	private static final int BASE = ALPHABET.length; // 62
	private static final BigInteger BASE_BI = BigInteger.valueOf(BASE);
	private static final int[] REVERSE_LOOKUP = init();

	private static final int[] init() {
		int[] array = new int[128];
		Arrays.fill(array, 0, array.length, 32);
		for (int i = 0; i < BASE; i++) {
			int charVal = (int) ALPHABET[i];
			array[charVal] = i;
		}
		return array;
	}

	public BijectiveUUIDEncoder() {
		super();
		digits = new ArrayList<Integer>();
		bb = ByteBuffer.wrap(new byte[16]);
	}
			
	public BigInteger getBigIntegerFromUUID(UUID randomUUID) {
		bb.putLong(randomUUID.getMostSignificantBits());
		bb.putLong(randomUUID.getLeastSignificantBits());
		BigInteger val = new BigInteger(1,bb.array());
		bb.flip();//prep for next use
		return val;
	}

	public UUID uuidFromBigInteger(BigInteger bi) {
		
		StringBuilder bis = new StringBuilder(bi.toString(16));
		if(bis.length() < 32) {
			int padlength = 32-bis.length();
			for(int i = 0;i<padlength;i++){
				bis.insert(0, '0');
			}
		}
	
		bis.insert(8, '-');
		bis.insert(13, '-');
		bis.insert(18, '-');
		bis.insert(23, '-');

		return java.util.UUID.fromString(bis.toString());
	}

	public String encode(UUID uuid) {

		BigInteger bi = getBigIntegerFromUUID(uuid);

		while (bi.compareTo(BigInteger.ZERO) > 0) {
			BigInteger remainder = bi.mod(BASE_BI);
			digits.add(remainder.intValue());
			bi = bi.divide(BASE_BI);
		}

		Collections.reverse(digits);
		StringBuilder buf = new StringBuilder();
		for (int i : digits) {
			buf.append(ALPHABET[i]);
		}

		digits.clear();

		return buf.toString();
	}

	public UUID decode(String str) {
		BigInteger value = BigInteger.ZERO;
		int exp = str.length() - 1;
		final int strLen = str.length();

		for (int count = 0; count < strLen; count++) {
			int pos = str.charAt(count);
			int i = REVERSE_LOOKUP[pos];
			BigInteger l = BigInteger.valueOf(i);
			BigInteger intermediate = l.multiply(BASE_BI.pow(exp));
			value = value.add(intermediate);
			exp--;
		}

		return uuidFromBigInteger(value);
	}

}
