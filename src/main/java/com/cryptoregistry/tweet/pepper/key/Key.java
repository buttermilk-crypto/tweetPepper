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

package com.cryptoregistry.tweet.pepper.key;
import java.util.Arrays;
import java.util.Base64;

/**
 * Base class to wrap bytes used as keys
 * 
 * @author Dave
 * @see CryptoFactory
 */
public class Key {
	
	// actual key bytes
	protected final byte [] bytes;
	
	// status of the key
	protected boolean alive = true;

	public Key(byte [] bytes) {
		this.bytes = bytes;
	}
	
	protected Key(byte [] bytes, boolean alive) {
		this.bytes = bytes;
		this.alive = alive;
	}

	public byte[] getBytes() {
		if(!alive) throw new DeadKeyException();
		return bytes;
	}
	
	public String getEncoded() {
		if(!alive) throw new DeadKeyException();
		return Base64.getUrlEncoder().encodeToString(bytes);
		
	}
	
	public void selfDestruct() {
		for(int i = 0;i<bytes.length;i++){
			bytes[i] = '\0';
		}
		alive = false;
	}

	public boolean isAlive() {
		return alive;
	}
	
	public int length() {
		return bytes.length;
	}
	
	public static class DeadKeyException extends RuntimeException {
		private static final long serialVersionUID = 1L;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (alive ? 1231 : 1237);
		result = prime * result + Arrays.hashCode(bytes);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Key other = (Key) obj;
		if (alive != other.alive)
			return false;
		if (!Arrays.equals(bytes, other.bytes))
			return false;
		return true;
	}

}
