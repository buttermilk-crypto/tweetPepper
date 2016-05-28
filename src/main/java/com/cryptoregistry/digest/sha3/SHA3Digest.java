/*
Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
Copyright 2016, David R. Smith, All Rights Reserved

This file is part of TweetPepper.

TweetPepper is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

TweetPepper is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TweetPepper.  If not, see <http://www.gnu.org/licenses/>.

 */
package com.cryptoregistry.digest.sha3;

/**
 * implementation of SHA-3 based on following KeccakNISTInterface.c from
 * http://keccak.noekeon.org/
 * <p>
 * Following the naming conventions used in the C source code to enable easy
 * review of the implementation.
 */
public class SHA3Digest extends KeccakDigest {
	private static int checkBitLength(int bitLength) {
		switch (bitLength) {
		case 224:
		case 256:
		case 384:
		case 512:
			return bitLength;
		default:
			throw new IllegalArgumentException("'bitLength' " + bitLength
					+ " not supported for SHA-3");
		}
	}

	public SHA3Digest() {
		this(256);
	}

	public SHA3Digest(int bitLength) {
		super(checkBitLength(bitLength));
	}

	public SHA3Digest(SHA3Digest source) {
		super(source);
	}

	public String getAlgorithmName() {
		return "SHA3-" + fixedOutputLength;
	}

	public int doFinal(byte[] out, int outOff) {
		absorb(new byte[] { 0x02 }, 0, 2);

		return super.doFinal(out, outOff);
	}

	/*
	 * TODO Possible API change to support partial-byte suffixes.
	 */
	protected int doFinal(byte[] out, int outOff, byte partialByte,
			int partialBits) {
		if (partialBits < 0 || partialBits > 7) {
			throw new IllegalArgumentException(
					"'partialBits' must be in the range [0,7]");
		}

		int finalInput = (partialByte & ((1 << partialBits) - 1))
				| (0x02 << partialBits);
		int finalBits = partialBits + 2;

		if (finalBits >= 8) {
			oneByte[0] = (byte) finalInput;
			absorb(oneByte, 0, 8);
			finalBits -= 8;
			finalInput >>>= 8;
		}

		return super.doFinal(out, outOff, (byte) finalInput, finalBits);
	}
}
