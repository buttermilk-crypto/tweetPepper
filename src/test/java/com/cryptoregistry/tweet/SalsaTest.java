package com.cryptoregistry.tweet;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Date;

import org.junit.Assert;
import org.junit.Test;

import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.TweetPepper;
import com.cryptoregistry.tweet.pepper.format.BlockFormatter;
import com.cryptoregistry.tweet.pepper.key.BoxingKeyContents;
import com.cryptoregistry.tweet.salt.TweetNaCl;
import com.cryptoregistry.tweet.salt.stream.Salsa20;

public class SalsaTest {

	@Test
	public void testSalsa20() {

		byte[] c = new byte[1000000]; // input text, 1Mb
		Arrays.fill(c, (byte) 0); // zero it
		byte[] n = new byte[Salsa20.CRYPTO_STREAM_SALSA20_REF_NONCEBYTES]; // nonce,
																			// 8
																			// bytes
		Arrays.fill(n, (byte) 32);
		byte[] k = new byte[Salsa20.CRYPTO_STREAM_SALSA20_REF_KEYBYTES]; // key
		Arrays.fill(k, (byte) 0); // zero it for a const key

		Salsa20 salsa = new Salsa20();
		Date start = new Date();
		salsa.crypto_stream(c, c.length, n, 0, k);
		Date stop = new Date();
		System.err.println("encrypt: " + (stop.getTime() - start.getTime())
				+ "ms");

		start = new Date();
		byte[] m = new byte[1000000]; // recovered input text
		salsa.crypto_stream_xor(c, m, m.length, n, 0, k);
		stop = new Date();
		System.err.println("decrypt: " + (stop.getTime() - start.getTime())
				+ "ms");

		TweetNaCl salt = new TweetNaCl();

		byte[] nonce = salt.gen_rand(TweetNaCl.BOX_NONCE_BYTES);

		// sender keys
		byte[] pk0 = new byte[TweetNaCl.BOX_PUBLIC_KEY_BYTES];
		byte[] sk0 = new byte[TweetNaCl.BOX_SECRET_KEY_BYTES];
		salt.crypto_box_keypair(pk0, sk0, false);

		// receiver keys
		byte[] pk1 = new byte[TweetNaCl.BOX_PUBLIC_KEY_BYTES];
		byte[] sk1 = new byte[TweetNaCl.BOX_SECRET_KEY_BYTES];
		salt.crypto_box_keypair(pk1, sk1, false);

		start = new Date();
		byte[] output = salt.crypto_box(c, nonce, pk1, sk0); // receiver public
																// and sender
																// secret keys
		stop = new Date();
		System.err.println("encrypt: " + (stop.getTime() - start.getTime())
				+ "ms");

		start = new Date();
		@SuppressWarnings("unused")
		byte[] result = salt.crypto_box_open(output, nonce, pk0, sk1);
		stop = new Date();
		System.err.println("decrypt: " + (stop.getTime() - start.getTime())+ "ms");

	}

	// http://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
	// TODO more tests and use test vectors
	public byte[] fromHex(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character
					.digit(s.charAt(i + 1), 16));
		}
		return data;
	}
	
	@Test
	public void testTweetPepper() {
		TweetPepper tp = new TweetPepper();
		BoxingKeyContents sender = tp.generateBoxingKeys();
		BoxingKeyContents receiver = tp.generateBoxingKeys();
		// the tweet pepper compiled class
		InputStream in = this.getClass().getResourceAsStream("/com/cryptoregistry/tweet/salt/TweetNaCl.class");
		Block block = tp.encryptSalsa20(receiver, sender, in);
		BlockFormatter bf = new BlockFormatter(block);
		System.err.println(bf.buildJSON().getJson());
		
		InputStream result = tp.decryptSalsa20(receiver, sender, block);
		ByteArrayInputStream bin = (ByteArrayInputStream) result;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		
				// take bytes from the input stream and put into out stream
				byte [] buf = new byte[1028];
				int len = 0;
			    while ((len = bin.read(buf, 0, buf.length)) != -1){
			       out.write(buf, 0, len);
			    }
		byte [] resultClassBytes = out.toByteArray(); 
		int expectedLength = Integer.parseInt(block.get("Input.Length"));
		Assert.assertTrue(expectedLength == resultClassBytes.length);
		
		
	}
	
	
}
