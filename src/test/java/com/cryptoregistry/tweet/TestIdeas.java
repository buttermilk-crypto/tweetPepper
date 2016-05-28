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
package com.cryptoregistry.tweet;


import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.cryptoregistry.tweet.pbe.PBE;
import com.cryptoregistry.tweet.pbe.PBEParams;
import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.TweetPepper;
import com.cryptoregistry.tweet.pepper.format.BlockFormatter;
import com.cryptoregistry.tweet.pepper.key.BoxingKeyContents;
import com.cryptoregistry.tweet.pepper.key.SigningKeyContents;
import com.cryptoregistry.tweet.salt.TweetNaCl;
import com.cryptoregistry.tweet.salt.TweetNaCl.InvalidSignatureException;
import com.lambdaworks.crypto.SCrypt;

public class TestIdeas {
	
	@BeforeClass
	public static void warning() {
		System.err.println("These tests take some time to run. Don't be alarmed.");
	}

	@Test
	public void testAuthEncrypt() {
		
		TweetNaCl salt = new TweetNaCl();
		
		// authenticated encryption 
		
		// sender keys
		byte [] pk0 = new byte[TweetNaCl.BOX_PUBLIC_KEY_BYTES];
		byte [] sk0 = new byte[TweetNaCl.BOX_SECRET_KEY_BYTES];
		int retVal = salt.crypto_box_keypair(pk0, sk0, false);
		Assert.assertEquals(0,retVal);
		
		// receiver keys
		byte [] pk1 = new byte[TweetNaCl.BOX_PUBLIC_KEY_BYTES];
		byte [] sk1 = new byte[TweetNaCl.BOX_SECRET_KEY_BYTES];
		retVal = salt.crypto_box_keypair(pk1, sk1, false);
		Assert.assertEquals(0,retVal);
		
		// message bytes
		byte [] msg = "Hello Tweet Salt".getBytes(StandardCharsets.UTF_8);
		byte [] nonce = salt.gen_rand(TweetNaCl.BOX_NONCE_BYTES);
		
		byte [] output = salt.crypto_box(msg, nonce, pk1, sk0); // receiver public and sender secret keys
		
		byte [] result = salt.crypto_box_open(output, nonce, pk0, sk1);
		Assert.assertTrue(Arrays.equals(msg, result));
		
	}
	
	/**
	 * A little different idea - crypto_sign returns a signed message, which is then converted back 
	 * to a message and validated. But is it also encrypted? Should this be passed, actually, a digest?
	 * 
	 */
	@Test
	public void testSignedMessage() {
		
		TweetNaCl salt = new TweetNaCl();
		
		// signature
		
		// signer keys
		byte [] pk0 = new byte[TweetNaCl.SIGN_PUBLIC_KEY_BYTES];
		byte [] sk0 = new byte[TweetNaCl.SIGN_SECRET_KEY_BYTES];
		salt.crypto_sign_keypair(pk0, sk0, false);
		
		// message bytes
		byte [] msg = "Hello Tweet Salt".getBytes(StandardCharsets.UTF_8);
		
		byte [] signedMsg = salt.crypto_sign(msg, sk0);
		
		// throws InvalidSignatureException if fails
		try {
			byte [] resultMsg = salt.crypto_sign_open(signedMsg, pk0);
			Assert.assertTrue(Arrays.equals(msg, resultMsg));
		}catch(InvalidSignatureException x){
			Assert.fail();
		}
	}
	
	@Test
	public void testSecretbox() {
		
		TweetNaCl salt = new TweetNaCl();
		
		// message bytes
		byte [] msg = "Hello Tweet Salt".getBytes(StandardCharsets.UTF_8);
		byte [] key = salt.gen_rand(TweetNaCl.BOX_SECRET_KEY_BYTES);
		byte [] nonce = salt.gen_rand(TweetNaCl.BOX_NONCE_BYTES);
		
		byte [] result = salt.secretbox(msg, nonce, key);
		Assert.assertTrue(Arrays.equals(msg, salt.secretbox_open(result, nonce, key)));
		
	}
	
	@Test
	public void testScrypt() throws Exception{
		    
		TweetNaCl salt = new TweetNaCl();
		
		// key derivation input
		String passwd = "password1";
		
		// we'll need to reserve this
		byte[] scryptsalt = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(scryptsalt);																	
        byte[] derived = SCrypt.scrypt(passwd.getBytes(StandardCharsets.UTF_8), scryptsalt, 16384, 256, 1, 32); //uses about 60Gb of ram
		
        // validate this key will match the expected size for secret box
		Assert.assertEquals(derived.length, TweetNaCl.BOX_SECRET_KEY_BYTES);
		
		byte [] nonce = salt.gen_rand(TweetNaCl.BOX_NONCE_BYTES);
		byte [] msg = "Hello Tweet Salt".getBytes(StandardCharsets.UTF_8);
		byte [] result = salt.secretbox(msg, nonce, derived);
		
		Assert.assertTrue(Arrays.equals(msg, salt.secretbox_open(result, nonce, derived)));
		
	}
	
	@Test
	public void predicateGeneration() {
		
		PBEParams params = new TweetPepper().createPBEParams(); // the default, takes about 10 seconds to run on my laptop
		Assert.assertTrue(params.N == 16384);
		Assert.assertTrue(params.r == 64);
		Assert.assertTrue(params.p == 1);
	}
	
	
	@Test
	public void testProtect() {
		
		// key derivation input
		String passwd = "password1";
		PBEParams params = new TweetPepper().createPBEParams();
		
		BoxingKeyContents contents = new TweetPepper().generateBoxingKeys();
		PBE pbe0 = new PBE(params);
		String X = pbe0.protect(passwd.toCharArray(), contents.secretBoxingKey.getBytes());
		System.err.println(X);
		
		PBE pbe1 = new PBE();
		byte [] confidential = pbe1.unprotect(passwd.toCharArray(), X);
		
		Assert.assertTrue(Arrays.equals(contents.secretBoxingKey.getBytes(),confidential));
	}
	
	@Test
	public void keyFromBlock() {
		SigningKeyContents contents = new TweetPepper().generateSigningKeys();
		Block ublock = contents.toBlock();
		Block pblock = contents.pubBlock();
		SigningKeyContents contents0 = new SigningKeyContents(ublock);
		Block ublock0 = contents0.toBlock();
		Block pblock0 = contents0.pubBlock();
		Assert.assertTrue(ublock.equals(ublock0));
		Assert.assertTrue(pblock.equals(pblock0));
	}
	
	@Test
	public void testEncrypt() {
		
		TweetPepper tp = new TweetPepper();
		BoxingKeyContents mine = tp.generateBoxingKeys();
		BoxingKeyContents theirs = tp.generateBoxingKeys();
	
		String msg = "Hello Tweet Salt Encryption";
		Block block = tp.encrypt(theirs, mine, msg);
		String result = tp.decrypt(theirs, mine, block);
		Assert.assertEquals(msg, result);
		
		System.err.println(new BlockFormatter(block).buildJSON().getJson());
		
	}
	
}
