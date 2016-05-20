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

package com.cryptoregistry.tweet.pepper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import com.cryptoregistry.tweet.pbe.PBE;
import com.cryptoregistry.tweet.pbe.PBEParams;
import com.cryptoregistry.tweet.pepper.key.BoxingKeyContents;
import com.cryptoregistry.tweet.pepper.key.BoxingKeyForPublication;
import com.cryptoregistry.tweet.pepper.key.PrivateKey;
import com.cryptoregistry.tweet.pepper.key.PublicKey;
import com.cryptoregistry.tweet.pepper.key.SecretBoxKeyContents;
import com.cryptoregistry.tweet.pepper.key.SecretKey;
import com.cryptoregistry.tweet.pepper.key.SigningKeyContents;
import com.cryptoregistry.tweet.pepper.key.TweetKeyMetadata;
import com.cryptoregistry.tweet.salt.TweetNaCl;
import com.cryptoregistry.tweet.salt.stream.Salsa20;

/**
 * Provide PKI support tailored for use specifically with TweetNacl
 * 
 * @author Dave
 * @see com.cryptoregistry.tweet.pepper.sig package for digital signature support classes
 */
public final class TweetPepper {

	private final SecureRandom rand = initRand();
	public final TweetNaCl salt = new TweetNaCl();

	public TweetPepper() {
		super();
	}

	private final SecureRandom initRand() {
		try {
			return SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Build a java object representation of a key for use in boxing using the crypto_box function.
	 * 
	 * @return
	 */
	public BoxingKeyContents generateBoxingKeys() {

		byte[] pk0 = new byte[TweetNaCl.BOX_PUBLIC_KEY_BYTES];
		byte[] sk0 = new byte[TweetNaCl.BOX_SECRET_KEY_BYTES];
		salt.crypto_box_keypair(pk0, sk0, false);
		BoxingKeyContents contents = new BoxingKeyContents(
				TweetKeyMetadata.createBoxingMetadata(BlockType.U),
				new PublicKey(pk0), new PrivateKey(sk0));
		return contents;
	}

	/**
	 * Build a java object representation of a key for use in signing.
	 * 
	 * @return
	 */
	public SigningKeyContents generateSigningKeys() {

		byte[] pk0 = new byte[TweetNaCl.SIGN_PUBLIC_KEY_BYTES];
		byte[] sk0 = new byte[TweetNaCl.SIGN_SECRET_KEY_BYTES];
		salt.crypto_sign_keypair(pk0, sk0, false);
		SigningKeyContents contents = new SigningKeyContents(
				TweetKeyMetadata.createSigningMetadata(BlockType.U),
				new PublicKey(pk0), new PrivateKey(sk0));
		return contents;
	}

	/**
	 * Build a java object representation of a key for use in secret key boxing. 
	 * 
	 * @return
	 */
	public final SecretBoxKeyContents generateSecretKey() {

		byte[] sk = new byte[TweetNaCl.BOX_SECRET_KEY_BYTES];
		rand.nextBytes(sk);
		SecretKey key = new SecretKey(sk);

		return new SecretBoxKeyContents(
				TweetKeyMetadata.createSecretBoxMetadata(BlockType.U), key);
	}

	/**
	 * Convenience method to build a PBEParam object. Note that these are one-use objects. 
	 * 
	 * @return
	 */
	public final PBEParams createPBEParams() {
		byte[] scryptSalt = new byte[16];
		rand.nextBytes(scryptSalt);
		byte[] secretBoxNonce = new byte[TweetNaCl.BOX_NONCE_BYTES];
		rand.nextBytes(secretBoxNonce);
		return new PBEParams(scryptSalt, secretBoxNonce);
	}
	
	/**
	 * <p>Return a Base64url encoded string, which is the parameters followed by an encrypted representation of 
	 * the confidentialBytes. Method:</p>
	 * 
	 * <ol>
	 *  <li>construct a parameter consisting of:</li>
	 *  	<ul>
	 *  		<li>a 16 byte random scrypt salt</li>
	 *  		<li>a 24 byte random nonce for the secretbox function</li>
	 *  		<li>N, r, and p values for scrypt. Defaults are N = 2^14, r = 2^8, p = 1.</li>
	 *  	</ul>
	 *  <li>The PBE builds an scrypt key from password, and then runs secretbox function
	 *      public byte[] secretbox(byte[] mesage, byte[] nonce, byte[] key);
	 *     </li>
	 *  <li>the output is encoded to a byte stream in the following fashion:</li>
	 *   <ul>
	 *   	<li>N (32 bit int), r (32 bit int), p (32 bit int), scrypt salt (16 bytes), secretbox nonce (24 bytes),
	 *   		and then the secret bytes (variable length). </li> 
	 *   </ul>
	 *  </ol>
	 *  
	 *  <p>Note: password cannot be null. Also, my default scrypt parameters do take some time to run:
	 *  perhaps 30 seconds on my old laptop. You can back off on these if you like to make encryption 
	 *  time faster.</p>
	 * 
	 * 
	 * @param password
	 * @param confidentialBytes
	 * @return an encrypted string
	 */
	public String protect(char [] password, byte [] confidentialBytes){
		if(password == null) throw new RuntimeException("password cannot be null.");
		PBEParams params = createPBEParams();
		PBE pbe = new PBE(params);
		return pbe.protect(password, confidentialBytes);
	}
	
	/**
	 * output the protected bytes. 
	 * 
	 * @param password
	 * @param protectedString
	 * @return
	 */
	public byte [] unprotect(char[]password, String protectedString){
		PBE pbe = new PBE();
		return pbe.unprotect(password, protectedString);
	}

	/**
	 * This is a basic TweetNaCL authenticated encryption using the crypto_box function. Emit a block of type E.
	 * This is best suited to smaller payloads. 
	 * 
	 * @param receiverPublicBoxingKey
	 * @param senderSecretBoxingKey
	 * @param in
	 * @return a Block of type E
	 */
	public Block encrypt(
			BoxingKeyForPublication receiverPublicBoxingKey,
			BoxingKeyContents senderSecretBoxingKey, 
			String in) {
		Block block = new Block(BlockType.E);
		byte[] nonce = new byte[TweetNaCl.BOX_NONCE_BYTES];
		rand.nextBytes(nonce);
		byte[] enc = salt.crypto_box(in.getBytes(StandardCharsets.UTF_8),
				nonce, receiverPublicBoxingKey.publicKey.getBytes(),
				senderSecretBoxingKey.secretBoxingKey.getBytes());

		block.put("S", senderSecretBoxingKey.metadata.handle);
		block.put("P", receiverPublicBoxingKey.metadata.handle);
		Encoder encoder = Base64.getUrlEncoder();
		block.put("Nonce.0", encoder.encodeToString(nonce));
		block.put("Data.0", encoder.encodeToString(enc));

		return block;
	}
	
	/**
	 * This is a basic TweetNaCL authenticated encryption using the crypto_box function. Emit a block of type E.
	 * This is best suited to smaller payloads. 
	 * 
	 * @param receiverPublicBoxingKey
	 * @param senderSecretBoxingKey
	 * @param in
	 * @return a Block of type E
	 */
	public Block encryptBytes(
			BoxingKeyForPublication receiverPublicBoxingKey,
			BoxingKeyContents senderSecretBoxingKey, 
			byte [] in) {
		Block block = new Block(BlockType.E);
		byte[] nonce = new byte[TweetNaCl.BOX_NONCE_BYTES];
		rand.nextBytes(nonce);
		byte[] enc = salt.crypto_box(in,
				nonce, 
				receiverPublicBoxingKey.publicKey.getBytes(),
				senderSecretBoxingKey.secretBoxingKey.getBytes());

		block.put("S", senderSecretBoxingKey.metadata.handle);
		block.put("P", receiverPublicBoxingKey.metadata.handle);
		Encoder encoder = Base64.getUrlEncoder();
		block.put("Nonce.0", encoder.encodeToString(nonce));
		block.put("Data.0", encoder.encodeToString(enc));

		return block;
	}

	/**
	 * Used to unbox the above 
	 * 
	 * @param receiverSecretBoxingKey
	 * @param senderPublicBoxingKey
	 * @param block
	 * @return a UTF-8 string, the unboxed result
	 */
	public String decrypt(
			BoxingKeyContents receiverSecretBoxingKey,
			BoxingKeyForPublication senderPublicBoxingKey, 
			Block block) {

		if (!block.get("S").equals(senderPublicBoxingKey.metadata.handle)) {
			throw new RuntimeException("looks like wrong key, expecting: "
					+ block.get("S"));
		}
		if (!block.get("P").equals(receiverSecretBoxingKey.metadata.handle)) {
			throw new RuntimeException("looks like wrong key, expecting: "
					+ block.get("P"));
		}

		Decoder decoder = Base64.getUrlDecoder();
		byte[] msg = salt.crypto_box_open(decoder.decode(block.get("Data.0")),
				decoder.decode(block.get("Nonce.0")),
				senderPublicBoxingKey.publicKey.getBytes(),
				receiverSecretBoxingKey.secretBoxingKey.getBytes());

		return new String(msg, StandardCharsets.UTF_8);
	}
	
	/**
	 * Used to unbox the above 
	 * 
	 * @param receiverSecretBoxingKey
	 * @param senderPublicBoxingKey
	 * @param block
	 * @return a raw byte array
	 */
	public byte [] decryptToBytes(
			BoxingKeyContents receiverSecretBoxingKey,
			BoxingKeyForPublication senderPublicBoxingKey, 
			Block block) {

		if (!block.get("S").equals(senderPublicBoxingKey.metadata.handle)) {
			throw new RuntimeException("looks like wrong key, expecting: "
					+ block.get("S"));
		}
		if (!block.get("P").equals(receiverSecretBoxingKey.metadata.handle)) {
			throw new RuntimeException("looks like wrong key, expecting: "
					+ block.get("P"));
		}

		Decoder decoder = Base64.getUrlDecoder();
		byte[] msg = salt.crypto_box_open(decoder.decode(block.get("Data.0")),
				decoder.decode(block.get("Nonce.0")),
				senderPublicBoxingKey.publicKey.getBytes(),
				receiverSecretBoxingKey.secretBoxingKey.getBytes());

		return msg;
	}

	/**
	 * Use crypto_box for key encapsulation and Salsa20 as the stream cipher. This is for larger inputs. There is a significant 
	 * improvement on speed this way for larger payloads (perhaps by a factor of 7) as compared to crypto_box 
	 * function by itself.
	 * 
	 * @param receiverPublicBoxingKey
	 * @param senderSecretBoxingKey
	 * @param in
	 * @return a block of type E with the encoded contents
	 */
	public Block encryptSalsa20(
			BoxingKeyForPublication receiverPublicBoxingKey,
			BoxingKeyContents senderSecretBoxingKey, 
			InputStream in) {
		
		Block block = new Block(BlockType.E);
		
		// transient, one-use values
		byte[] nonce = new byte[TweetNaCl.BOX_NONCE_BYTES];
		rand.nextBytes(nonce);
		byte [] key = new byte[TweetNaCl.BOX_SECRET_KEY_BYTES];
		rand.nextBytes(key);
		byte[] n = new byte[Salsa20.CRYPTO_STREAM_SALSA20_REF_NONCEBYTES];
		rand.nextBytes(n);
		
		// key encapsulation
		byte[] enc = salt.crypto_box(key,
				nonce, 
				receiverPublicBoxingKey.publicKey.getBytes(),
				senderSecretBoxingKey.secretBoxingKey.getBytes());
		
		 Salsa20 salsa = new Salsa20();
		 ByteArrayOutputStream bos = new ByteArrayOutputStream(); // result of encryption collected here
		 int sum = 0;
		 
		 try {
		// take bytes from the input stream and encrypt
		byte [] buf = new byte[1028];
		int len = 0;
		
	      while ((len = in.read(buf, 0, buf.length)) != -1){
	  		salsa.crypto_stream(buf, len, n, 0, key);
	        bos.write(buf, 0, len);
	        sum+=len;
	      }
	      
		 }catch(IOException x) {
			 throw new RuntimeException(x);
		 }

		block.put("S", senderSecretBoxingKey.metadata.handle);
		block.put("P", receiverPublicBoxingKey.metadata.handle);
		
		Encoder encoder = Base64.getUrlEncoder();
		block.put("Nonce.0", encoder.encodeToString(nonce));
		block.put("EncapsulatedKey", encoder.encodeToString(enc));
		block.put("StreamAlg", "Salsa20");
		block.put("StreamNonce.0", encoder.encodeToString(n));
		block.put("Data.0", encoder.encodeToString(bos.toByteArray()));
		block.put("Input.Length", String.valueOf(sum));

		return block;
	}
	
	/**
	 * Decrypt the above (using crypto_box for key encapsulation and Salsa20 as the stream cipher). 
	 * 
	 * @param receiverPublicBoxingKey
	 * @param senderSecretBoxingKey
	 * @param in
	 * @return a ByteArrayInputStream
	 * 
	 */
	public InputStream decryptSalsa20(
			BoxingKeyContents receiverSecretBoxingKey,
			BoxingKeyForPublication senderPublicBoxingKey, 
			Block block) {
		
		if (!block.get("S").equals(senderPublicBoxingKey.metadata.handle)) {
			throw new RuntimeException("looks like wrong key, expecting: "
					+ block.get("S"));
		}
		if (!block.get("P").equals(receiverSecretBoxingKey.metadata.handle)) {
			throw new RuntimeException("looks like wrong key, expecting: "
					+ block.get("P"));
		}

		Decoder decoder = Base64.getUrlDecoder();
		byte[] key = salt.crypto_box_open(decoder.decode(block.get("EncapsulatedKey")),
				decoder.decode(block.get("Nonce.0")),
				senderPublicBoxingKey.publicKey.getBytes(),
				receiverSecretBoxingKey.secretBoxingKey.getBytes());
		
		String streamingAlg = block.get("StreamAlg");
		byte [] streamNonce = block.getBytesFromBase64urlString("StreamNonce.0");
		
		switch(streamingAlg){
		
			case "Salsa20" :{
				Salsa20 salsa = new Salsa20();
				byte [] data = block.getBytesFromBase64urlString("Data.0");
				byte [] raw = new byte[data.length];
				salsa.crypto_stream_xor(data, raw, raw.length, streamNonce, 0, key);
				ByteArrayInputStream out = new ByteArrayInputStream(raw);
				return out;
			}
			default: throw new RuntimeException("Unexpected algorithm: "+streamingAlg);
		}
	}

}
