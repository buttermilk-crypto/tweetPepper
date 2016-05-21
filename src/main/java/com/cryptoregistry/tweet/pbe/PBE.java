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

package com.cryptoregistry.tweet.pbe;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Base64;

import com.cryptoregistry.tweet.salt.TweetNaCl;
import com.lambdaworks.crypto.SCrypt;

/**
 * Simple to use but powerful PBE based on scrypt and secretbox.
 * 
 * @author Dave
 *
 */
public class PBE {

	private final PBEParams params;

	/**
	 * Used with protect()
	 * 
	 * @param params
	 */
	public PBE(PBEParams params) {
		super();
		this.params = params;
		if(this.params.N == 0 || this.params.r == 0 || this.params.p == 0) throw new RuntimeException("Invalid SCrypt predicates");
	}

	/**
	 * Used with unprotect()
	 */
	public PBE() {
		super();
		this.params = null;
	}

	/**
	 * Protect some bytes using our SCrypt/SecretBox algorithm. password is zeroed out as a side-effect. 
	 * 
	 * @param password
	 * @param confidentialBytes
	 * @return a String, the Base64url encoded bytes prepended with a header containing the parameters
	 * 
	 */
	public String protect(char[] password, byte[] confidentialBytes) {
		if (params == null) throw new RuntimeException("Need to set params in constructor first before this call.");
		if (password == null) throw new RuntimeException("Password cannot be null.");
		TweetNaCl salt = new TweetNaCl();
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DataOutputStream doubt = new DataOutputStream(out);
		try {
			// the pbe key
			byte[] derived = SCrypt.scrypt(toBytes(password),
					params.scryptSalt, params.N, params.r, params.p, 32);
			
			doubt.writeByte((byte)'t');
			doubt.writeByte((byte)'p');
			doubt.writeShort(params.N); // 2 bytes
			doubt.writeShort(params.r); // 2 bytes
			doubt.writeShort(params.p);  // 2 bytes
			doubt.write(params.scryptSalt); // 16 bytes
			doubt.write(params.nonce); // 24 bytes
			
			byte[] enc = salt.secretbox(confidentialBytes, params.nonce,derived);
			
			doubt.write(enc); // variable length?
			doubt.flush();

			String encoded = Base64.getUrlEncoder().encodeToString(out.toByteArray());
			cleanup(password); // clear password
			return encoded;
		} catch (Exception x) {
			throw new RuntimeException(x);
		}
	}

	/**
	 * decrypt our protected bytes and return them. password is zeroed out as a side effect of this method 
	 * 
	 * @param password
	 * @param protectedString
	 * @return the confidential bytes
	 */
	public byte [] unprotect(char[] password, String protectedString) {

		TweetNaCl salt = new TweetNaCl();

		try {
			byte[] packed = Base64.getUrlDecoder().decode(protectedString);
			ByteArrayInputStream bin = new ByteArrayInputStream(packed);
			DataInputStream in = new DataInputStream(bin);
			char first = (char)in.readByte();
			char second = (char)in.readByte();
			if(!(first == 't' && second == 'p')){
				throw new RuntimeException("Magic does not match: "+first+""+second+"input is not encoded as expected");
			}
			int N = in.readShort();
			int r = in.readShort();
			int p = in.readShort();
			byte [] scryptSalt = new byte[16];
			in.readFully(scryptSalt);
			byte [] nonce = new byte[TweetNaCl.BOX_NONCE_BYTES];
			in.readFully(nonce);
			byte [] enc = new byte[packed.length - (2+2+2+2+16+TweetNaCl.BOX_NONCE_BYTES)];
			in.readFully(enc);
			
			// the pbe key
			byte[] derived = SCrypt.scrypt(toBytes(password), scryptSalt, N, r, p, 32);
			
			// unboxing
			byte [] confidential = salt.secretbox_open(enc, nonce, derived);
			cleanup(password);
			return confidential;

		} catch (Exception x) {
			throw new RuntimeException(x);
		}
	}

	private void cleanup(char[] array) {
		Arrays.fill(array, '\u0000');
	}

	private byte[] toBytes(char[] password) {
		CharBuffer charBuffer = CharBuffer.wrap(password);
		ByteBuffer byteBuffer = Charset.forName("UTF-8").encode(charBuffer);
		byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
				byteBuffer.position(), byteBuffer.limit());
		Arrays.fill(charBuffer.array(), '\u0000'); // clear sensitive data
		Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
		return bytes;
	}

}
