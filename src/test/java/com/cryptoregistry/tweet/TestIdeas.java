package com.cryptoregistry.tweet;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

import com.cryptoregistry.tweet.salt.TweetNaCl;
import com.cryptoregistry.tweet.salt.TweetNaCl.InvalidSignatureException;

public class TestIdeas {

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
		byte [] key = new byte[TweetNaCl.BOX_SECRET_KEY_BYTES];
		byte [] nonce = salt.gen_rand(TweetNaCl.BOX_NONCE_BYTES);
		
		byte [] result = salt.secretbox(msg, nonce, key);
		
	}
}
