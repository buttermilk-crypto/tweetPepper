package com.cryptoregistry.tweet.pepper;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import com.cryptoregistry.tweet.pbe.PBEParams;
import com.cryptoregistry.tweet.pepper.key.BoxingKeyContents;
import com.cryptoregistry.tweet.pepper.key.PrivateKey;
import com.cryptoregistry.tweet.pepper.key.PublicKey;
import com.cryptoregistry.tweet.pepper.key.SecretBoxKeyContents;
import com.cryptoregistry.tweet.pepper.key.SecretKey;
import com.cryptoregistry.tweet.pepper.key.SigningKeyContents;
import com.cryptoregistry.tweet.pepper.key.TweetKeyMetadata;
import com.cryptoregistry.tweet.salt.TweetNaCl;

/**
 * Provide new PKI support tailored for use specifically with TweetNacl
 * 
 * @author Dave
 *
 */
public final class TweetPepper {
	
	private static final SecureRandom rand = initRand();
	
	private static SecureRandom initRand() {
		try {
			return SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static final BoxingKeyContents generateBoxingKeys() {
		
		TweetNaCl salt = new TweetNaCl();

		byte [] pk0 = new byte[TweetNaCl.BOX_PUBLIC_KEY_BYTES];
		byte [] sk0 = new byte[TweetNaCl.BOX_SECRET_KEY_BYTES];
		salt.crypto_box_keypair(pk0, sk0, false);
		BoxingKeyContents contents = new BoxingKeyContents(
				TweetKeyMetadata.createMetadata(BlockType.U),
				new PublicKey(pk0),
				new PrivateKey(sk0)
		);
		return contents;
	}
	
	public static final SigningKeyContents generateSigningKeys() {
		
		TweetNaCl salt = new TweetNaCl();

		byte [] pk0 = new byte[TweetNaCl.SIGN_PUBLIC_KEY_BYTES];
		byte [] sk0 = new byte[TweetNaCl.SIGN_SECRET_KEY_BYTES];
		salt.crypto_sign_keypair(pk0, sk0, false);
		SigningKeyContents contents = new SigningKeyContents(
				TweetKeyMetadata.createMetadata(BlockType.U),
				new PublicKey(pk0),
				new PrivateKey(sk0)
		);
		return contents;
	}
	
	public static final SecretBoxKeyContents generateSecretKey() {
		
		byte [] sk = new byte[TweetNaCl.BOX_SECRET_KEY_BYTES];
		rand.nextBytes(sk);
		SecretKey key = new SecretKey(sk); 
		
		return new SecretBoxKeyContents(TweetKeyMetadata.createMetadata(BlockType.U), key);
	}
	
	public static final PBEParams createPBEParams(){
		byte [] scryptSalt = new byte [16];
		rand.nextBytes(scryptSalt);
		byte [] secretBoxNonce = new byte [TweetNaCl.BOX_NONCE_BYTES];
		rand.nextBytes(secretBoxNonce);
		return new PBEParams(scryptSalt,secretBoxNonce);
	}

}
