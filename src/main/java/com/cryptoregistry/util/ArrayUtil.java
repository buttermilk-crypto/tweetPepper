/*
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
package com.cryptoregistry.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class ArrayUtil {

	private static Lock lock = new ReentrantLock();
	
	public static String encode1dShort(short[] array) {
		lock.lock();
		try {
			int outerSize = array.length;

			try (ByteArrayOutputStream orig = new ByteArrayOutputStream();
					DataOutputStream out = new DataOutputStream(orig);) {
				out.writeShort(outerSize);
				for (int i = 0; i < outerSize; i++) {
						out.writeShort(array[i]);
				}
				return Base64.getUrlEncoder().encodeToString(orig.toByteArray());
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		} finally {
			lock.unlock();
		}
	}
	
	public static short[] decode1dShort(String encoded) {
		lock.lock();
		try {
			short[] primary = null;
			try {
				byte[] inbytes = Base64.getUrlDecoder().decode(encoded);
				ByteArrayInputStream in = new ByteArrayInputStream(inbytes);
				DataInputStream instream = new DataInputStream(in);
				int firstLevel = instream.readShort();
				if (firstLevel == 0)
					throw new RuntimeException(
						"array dimensions look incorrect, should be non-zero:"+ firstLevel);
				primary = new short[firstLevel];
				for (int i = 0; i < firstLevel; i++) {
						primary[i] = instream.readShort();
				}
			} catch (IOException e) {
				throw new RuntimeException(e);
			}

			return primary;
			
		} finally {
			lock.unlock();
		}
	}

}
