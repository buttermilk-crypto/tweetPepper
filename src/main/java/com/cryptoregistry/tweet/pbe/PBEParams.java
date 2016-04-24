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
		this.r = 256;
		this.p = 1;
	}

}
