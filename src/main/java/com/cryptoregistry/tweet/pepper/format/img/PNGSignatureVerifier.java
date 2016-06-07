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
package com.cryptoregistry.tweet.pepper.format.img;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import com.cryptoregistry.digest.sha3.SHA3Digest;
import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.BlockType;
import com.cryptoregistry.tweet.pepper.KMU;
import com.cryptoregistry.tweet.pepper.format.KMUInputAdapter;
import com.cryptoregistry.tweet.pepper.sig.TweetPepperVerifier;

/**
 * <p>This class will search the input stream (which must be in valid PNG format) and look for a tpSi chunk.
 * It will validate the contents of the signature as good, then compare the current IDAT chunk data digest
 * with the signed one. If the IDAT data digests are equal, verify() will return true</p>
 * 
 * <p>This class does not require a graphics context.</p>
 * 
 * @author Dave
 * @see PNGSigner 
 */
public class PNGSignatureVerifier extends Constants {

	final InputStream in;
	public final SHA3Digest digest;
	public final boolean keep;
	
	// these will be null until verify is run
	private KMU keyStoreKMU;
	private KMU signatureKMU;
	
	public PNGSignatureVerifier(InputStream in) {
		this.in = in;
		digest = new SHA3Digest();
		keep = false;
	}
	
	/**
	 * If keepData is true, the methods getKeystore() and getSignature() will return a value after verify() is run
	 * 
	 * @param in
	 * @param keepData
	 */
	public PNGSignatureVerifier(InputStream in, boolean keepData) {
		this.in = in;
		digest = new SHA3Digest();
		keep = true;
	}
	
	/**
	 * Return true if the currently computed digest matches the previously signed one
	 * 
	 * @return
	 * @throws IOException
	 */
	
	public boolean verify() throws IOException {
	
		boolean result = false;
		DataInputStream din = new DataInputStream(in);
	
		// consume and test header
		byte[]header = new byte[8];
		din.readFully(header, 0, 8);
		if(!Arrays.equals(Constants.HEADER, header)) fail("Header does not look like png format");
	
		// loop through the chunks
		control: while(true){
			
			Chunk c = this.readChunk(din);
			
			switch(c.chunkType){
			    case "IHDR":
				case "IDAT": {
					digest.update(c.data, 0, (int)c.uInt);
					break;
				}
				case "tpKe": {
					// if we find a TweetPepper key store, include in digest
					digest.update(c.data, 0, (int)c.uInt);
					if(keep) {
						byte [] jsonBytes = decompress(c.data);
						String str = new String(jsonBytes, StandardCharsets.UTF_8);
						StringReader json = new StringReader(str);
						KMUInputAdapter inAdapter = new KMUInputAdapter(json);
						this.keyStoreKMU = inAdapter.read();
					}
					break;
				}
				case "tpSi": {
					// ok, found our signature chunk, unpack it.
					byte [] jsonBytes = decompress(c.data);
					String str = new String(jsonBytes, StandardCharsets.UTF_8);
					StringReader json = new StringReader(str);
					KMUInputAdapter inAdapter = new KMUInputAdapter(json);
					KMU kmu = inAdapter.read();
					if(keep){
						this.signatureKMU=kmu;
					}
					
					TweetPepperVerifier verifier = new TweetPepperVerifier();
					verifier.addKMUBlocks(kmu);
					
					// Step 1. check to see if the stored signature over the previous digest is valid.
					boolean sigIsGood = verifier.verify();
					
					if(sigIsGood) {
						
						// Step 2, is the stored digest in the D block equal to the currently computed digest?
						// assign the answer to result
						byte [] hash = new byte[digest.getDigestSize()];
						digest.doFinal(hash, 0);
						Block datablock = kmu.findBlock(BlockType.D); // find the first Data block
						String base64 = datablock.get("digest.0.base64url");
						byte [] digestBytes = Base64.getUrlDecoder().decode(base64);
						result = Arrays.equals(hash, digestBytes);
						
					}else{
						result = sigIsGood;
					}
					
				    break control;
				}
				case "IEND": break control;
				default:{
					// do nothing 
				}
			}
		
		}// end while
		
		return result;
	}

	public KMU getKeyStore() {
		return keyStoreKMU;
	}

	public KMU getSignature() {
		return signatureKMU;
	}	
	
	

}
