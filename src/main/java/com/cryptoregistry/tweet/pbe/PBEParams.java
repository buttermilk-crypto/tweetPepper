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

/**
 * These are predicates to the key derivation function and secret box encryption of the private key.
 * We need to serialize these along with the encryption as they are required for reconstitution 
 * of the encrypted string
 * 
 * @author Dave
 *
 */
public class PBEParams {

	public final byte [] scryptSalt;
	public final byte [] nonce;
	public final int N, r, p;
	
	public PBEParams(byte[] scryptSalt, byte[] nonce, int n, int r, int p) {
		super();
		this.scryptSalt = scryptSalt;
		this.nonce = nonce;
		this.N = n;
		this.r = r;
		this.p = p;
	}
	
	// the settings I use locally
	public PBEParams(byte[] scryptSalt, byte[] nonce) {
		super();
		this.scryptSalt = scryptSalt;
		this.nonce = nonce;
		this.N = 16384; // 2^14
		this.r = 64; //2^6 - memory cost adjustment
		this.p = 1; // cpu cost adjustment
	}

}
