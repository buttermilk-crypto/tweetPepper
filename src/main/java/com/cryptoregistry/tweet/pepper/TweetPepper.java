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
 *
 */
public class TweetPepper {

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

	public BoxingKeyContents generateBoxingKeys() {

		byte[] pk0 = new byte[TweetNaCl.BOX_PUBLIC_KEY_BYTES];
		byte[] sk0 = new byte[TweetNaCl.BOX_SECRET_KEY_BYTES];
		salt.crypto_box_keypair(pk0, sk0, false);
		BoxingKeyContents contents = new BoxingKeyContents(
				TweetKeyMetadata.createBoxingMetadata(BlockType.U),
				new PublicKey(pk0), new PrivateKey(sk0));
		return contents;
	}

	public SigningKeyContents generateSigningKeys() {

		byte[] pk0 = new byte[TweetNaCl.SIGN_PUBLIC_KEY_BYTES];
		byte[] sk0 = new byte[TweetNaCl.SIGN_SECRET_KEY_BYTES];
		salt.crypto_sign_keypair(pk0, sk0, false);
		SigningKeyContents contents = new SigningKeyContents(
				TweetKeyMetadata.createSigningMetadata(BlockType.U),
				new PublicKey(pk0), new PrivateKey(sk0));
		return contents;
	}

	public final SecretBoxKeyContents generateSecretKey() {

		byte[] sk = new byte[TweetNaCl.BOX_SECRET_KEY_BYTES];
		rand.nextBytes(sk);
		SecretKey key = new SecretKey(sk);

		return new SecretBoxKeyContents(
				TweetKeyMetadata.createSecretBoxMetadata(BlockType.U), key);
	}

	public final PBEParams createPBEParams() {
		byte[] scryptSalt = new byte[16];
		rand.nextBytes(scryptSalt);
		byte[] secretBoxNonce = new byte[TweetNaCl.BOX_NONCE_BYTES];
		rand.nextBytes(secretBoxNonce);
		return new PBEParams(scryptSalt, secretBoxNonce);
	}

	/**
	 * This is a basic encryption using the crypto_box function directly on input
	 * 
	 * @param receiverPublicBoxingKey
	 * @param senderSecretBoxingKey
	 * @param in
	 * @return
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
	 * Used to unbox the above 
	 * 
	 * @param receiverSecretBoxingKey
	 * @param senderPublicBoxingKey
	 * @param block
	 * @return
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
	 * Use crypto_box for key encapsulation and Salsa20 as the stream cipher. This is for larger inputs. There is a significant 
	 * improvement on speed this way perhaps by a factor of 10.
	 * 
	 * @param receiverPublicBoxingKey
	 * @param senderSecretBoxingKey
	 * @param in
	 * @return a block with the encoded contents
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
	 * Decrypt using crypto_box for key encapsulation and Salsa20 as the stream cipher. 
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
