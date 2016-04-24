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
 * One-use class, erases bytes so nonce, etc., cannot be reused by accident
 * 
 * @author Dave
 *
 */
public class PBE {

	private final PBEParams params;

	public PBE(PBEParams params) {
		super();
		this.params = params;
		if(this.params.N == 0 || this.params.r == 0 || this.params.p == 0) throw new RuntimeException("Invalid Script predicates");
		if(empty(params.nonce)) throw new RuntimeException("Nonce looks previously used");;
		if(empty(params.scryptSalt)) throw new RuntimeException("salt looks previously used");;
	}

	/**
	 * Used with unprotect
	 */
	public PBE() {
		super();
		this.params = null;
	}

	public String protect(char[] password, byte[] confidentialBytes) {
		if (params == null)
			throw new RuntimeException(
					"Need to set params in constructor first before this call.");
		if(empty(password)) 
			throw new RuntimeException("Password cannot be empty.");
		
		TweetNaCl salt = new TweetNaCl();
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DataOutputStream doubt = new DataOutputStream(out);
		try {
			// the pbe key
			byte[] derived = SCrypt.scrypt(toBytes(password),
					params.scryptSalt, params.N, params.r, params.p, 32);
			
			doubt.writeInt(params.N);
			doubt.writeInt(params.r);
			doubt.writeInt(params.p);
			doubt.write(params.scryptSalt); // 16 bytes
			doubt.write(params.nonce); // 24 bytes
			
			byte[] enc = salt.secretbox(confidentialBytes, params.nonce,derived);
			
			doubt.write(enc); // variable length?
			doubt.flush();

			String encoded = Base64.getUrlEncoder().encodeToString(out.toByteArray());
			cleanup(password); // clear password
			cleanup(params.nonce);
			cleanup(params.scryptSalt);
			return encoded;
		} catch (Exception x) {
			throw new RuntimeException(x);
		}
	}

	public byte [] unprotect(char[] password, String protectedString) {

		TweetNaCl salt = new TweetNaCl();

		try {
			byte[] packed = Base64.getUrlDecoder().decode(protectedString);
			ByteArrayInputStream bin = new ByteArrayInputStream(packed);
			DataInputStream in = new DataInputStream(bin);
			int N = in.readInt();
			int r = in.readInt();
			int p = in.readInt();
			byte [] scryptSalt = new byte[16];
			in.readFully(scryptSalt);
			byte [] nonce = new byte[TweetNaCl.BOX_NONCE_BYTES];
			in.readFully(nonce);
			byte [] enc = new byte[packed.length -(4+4+4+16+TweetNaCl.BOX_NONCE_BYTES)];
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
	
	private void cleanup(byte[] array) {
		Arrays.fill(array, (byte)0);
	}
	
	private boolean empty(byte[]array){
		int sum = 0;
		for(byte b: array){
			sum+=b;
		}
		return sum==0;
	}
	
	private boolean empty(char[]array){
		int sum = 0;
		for(int b: array){
			sum+=b;
		}
		return sum==0;
	}

	public byte[] toBytes(char[] password) {
		CharBuffer charBuffer = CharBuffer.wrap(password);
		ByteBuffer byteBuffer = Charset.forName("UTF-8").encode(charBuffer);
		byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
				byteBuffer.position(), byteBuffer.limit());
		Arrays.fill(charBuffer.array(), '\u0000'); // clear sensitive data
		Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
		return bytes;
	}

}
