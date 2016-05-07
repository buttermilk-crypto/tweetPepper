package com.cryptoregistry.tweet.url;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * <pre>
 * Bijective conversion between natural numbers (IDs) and short strings.
 *
 * Algorithm is due to http://stackoverflow.com/questions/742013/how-to-code-a-url-shortener
 * 
 * </pre>
 * 
 * @author Dave
 */
public final class ShortID {

	private final List<Integer> digits;

	private static final char[] ALPHABET = { '0', '1', '2', '3', '4', '5', '6',
			'7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
			'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
			'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
			'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
			'X', 'Y', 'Z' };

	private static final int BASE = ALPHABET.length; // 62
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
	
	public ShortID() {
		super();
		digits = new ArrayList<Integer>();
	}

	public String encode(int num) {

		while (num > 0) {
			int remainder = num % BASE;
			digits.add(remainder);
			num = num / BASE;
		}
		
		Collections.reverse(digits);
		StringBuilder buf = new StringBuilder();
		for (Integer i : digits) {
			buf.append(ALPHABET[i.intValue()]);
		}

		digits.clear();

		return buf.toString();
	}
	

	public int decode(String str) {
		int value = 0;
		int exp = str.length() - 1;
		final int strLen = str.length();
		for (int count = 0;count<strLen;count++) {
			int i = REVERSE_LOOKUP[(int) str.charAt(count)];
			double intermediate = i * Math.pow(BASE, exp);
			value += intermediate;
			exp--;
		}
		return value;
	}

}
