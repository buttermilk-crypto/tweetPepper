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

package com.cryptoregistry.tweet.pepper.sig;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.cryptoregistry.digest.cubehash.CubeHash224;
import com.cryptoregistry.digest.cubehash.CubeHash256;
import com.cryptoregistry.digest.cubehash.CubeHash384;
import com.cryptoregistry.digest.cubehash.CubeHash512;
import com.cryptoregistry.digest.cubehash.CubeHashCore;
import com.cryptoregistry.digest.sha3.SHA3Digest;
import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.KMU;
import com.cryptoregistry.tweet.pepper.key.SigningKeyForPublication;
import com.cryptoregistry.tweet.salt.TweetNaCl;
import com.cryptoregistry.tweet.salt.TweetNaCl.InvalidSignatureException;

/**
 * One of the blocks included must be a signature block and we will assume 
 * all the required info for validation will be present in the remaining blocks 
 * 
 * @author Dave
 *
 */
public class TweetPepperVerifier {
	
	protected final List<Block> blocks;

	public TweetPepperVerifier() {
		blocks = new ArrayList<Block>();
	}
	
	public void addBlock(Block block){
		blocks.add(block);
	}

	public TweetPepperVerifier addKMUBlocks(KMU kmu){
		for(String key: kmu.map.keySet()) {
			blocks.add(kmu.map.get(key));
		}
		return this;
	}
	
	public boolean verify() {
		
		// algorithm - 
		// 1.0 - find the signature block. Assume for the moment there is only one.
		
		Block sigBlock = null;
		for(Block b: blocks){
			if(b.name.endsWith("-S")){
				sigBlock = b;
				break;
			}
		}
		
		if(sigBlock == null) throw new RuntimeException("Could not find a suitable signing block (-S)");
		
		// 1.1 - within the signature block is the name of the public key block and other items, find them
		
		final String signedWith = sigBlock.get("SignedWith");
	//	final String signedBy = sigBlock.get("SignedBy");
		final String digestAlgorithm = sigBlock.get("DigestAlgorithm");
		final String sig = sigBlock.get("s");
		final String dataRefs = sigBlock.get("DataRefs");
	//	final String signatureDateOfRecord = sigBlock.get("CreateOn");
		
		// 1.2 - now locate the for-publication block (must be a signing key, not boxing) and rehydrate the key
		
		Block keyBlock = null;
		for(Block b: blocks){
			if(b.name.endsWith("-P") && b.name.startsWith(signedWith)){
				keyBlock = b;
				break;
			}
		}
		
		if(keyBlock == null) throw new RuntimeException("Could not find a suitable signing public key");
		
		SigningKeyForPublication verifierKey = new SigningKeyForPublication(keyBlock);
		
		// short circuit if needed, we take a different pathway for SHA-3
		if(digestAlgorithm.contains("SHA")){
			return verifySha(verifierKey, dataRefs, sig);
		}
		
		// this is the CubeHash pathway
		
		// 1.3 - create the appropriate Digest object
		CubeHashCore digest = null;
		switch(digestAlgorithm){
			case "CubeHash-224": digest = new CubeHash224(); break;
			case "CubeHash-256": digest = new CubeHash256(); break;
			case "CubeHash-384": digest = new CubeHash384(); break;
			case "CubeHash-512": digest = new CubeHash512(); break;
			case "CubeHash224": digest = new CubeHash224(); break;
			case "CubeHash256": digest = new CubeHash256(); break;
			case "CubeHash384": digest = new CubeHash384(); break;
			case "CubeHash512": digest = new CubeHash512(); break;
			default: {throw new RuntimeException("Unknown digest algorithm, giving up:"+digestAlgorithm); }
		}
		
		// 1.4 - construct a map of the possible data with uuid:key <-> value entries; 
		// this is the signature's available validation scope; it includes the Signature block contents itself
		
		Map<String,String> scope = new HashMap<String,String>();
		for(Block block: blocks){
			block.loadToSignatureScope(scope);
		}
		
		//	System.err.println(scope);
		
		// 1.5.1 - run a loop on the data ref list. The token items will be normalized in the pass.
		// find the data items and digest in order
		
		String currentUUID = null;
		String [] refs = dataRefs.split("\\,");
		for(String ref: refs) {
			
			// 1.5.1.0 - the ref has whitespace to cleanup 
			ref = ref.trim();
			
			// 1.5.1.1 - if it does not start with a ., it has a distinguished form, harvest the uuid for later use
			if(!ref.startsWith(".")){
				currentUUID = ref.split("\\:")[0];
			}else{
				// 1.5.1.2 - patch using currentUUID
				ref = currentUUID+":"+ref.substring(1);
			}
			
			// 1.5.1.3 - ok, now start testing the scope for items. It is an error if an expected 
			// item is not present in the scope
			String value = scope.get(ref);
			if(value == null) throw new RuntimeException("Missing value in scope map, ref:"+ref);
			digest.update(value.getBytes(StandardCharsets.UTF_8));
		}
		
		// 1.5.2 - digest complete. input to crypto_sign_open
		byte [] digestBytes = digest.digest();
		byte [] sigBytes = Base64.getUrlDecoder().decode(sig);
		try {
			byte [] outsign = new TweetNaCl().crypto_sign_open(sigBytes, verifierKey.publicKey.getBytes());
			return Arrays.equals(digestBytes, outsign);
		}catch(InvalidSignatureException x){
			return false;
		}
	}
	
	private boolean verifySha(SigningKeyForPublication verifierKey, String dataRefs, String sig){
		
		// BC-derived code has a different interface for digests
		SHA3Digest digest = new SHA3Digest();
		
		// 1.4 - construct a map of the possible data with uuid:key <-> value entries; 
		// this is the signature's available validation scope; it includes the Signature block contents itself
		
		Map<String,String> scope = new HashMap<String,String>();
		for(Block block: blocks){
			block.loadToSignatureScope(scope);
		}
		
		//	System.err.println(scope);
		
		// 1.5.1 - run a loop on the data ref list. The token items will be normalized in the pass.
		// find the data items and digest in order
		
		String currentUUID = null;
		String [] refs = dataRefs.split("\\,");
		for(String ref: refs) {
			
			// 1.5.1.0 - the ref has whitespace to cleanup 
			ref = ref.trim();
			
			// 1.5.1.1 - if it does not start with a ., it has a distinguished form, harvest the uuid for later use
			if(!ref.startsWith(".")){
				currentUUID = ref.split("\\:")[0];
			}else{
				// 1.5.1.2 - patch using currentUUID
				ref = currentUUID+":"+ref.substring(1);
			}
			
			// 1.5.1.3 - ok, now start testing the scope for items. It is an error if an expected 
			// item is not present in the scope
			String value = scope.get(ref);
			if(value == null) throw new RuntimeException("Missing value in scope map, ref:"+ref);
			byte [] bytes = value.getBytes(StandardCharsets.UTF_8);
			digest.update(bytes, 0, bytes.length);
		}
		
		// 1.5.2 - digest complete. input to crypto_sign_open
		byte [] digestBytes = new byte[digest.getDigestSize()];
		digest.doFinal(digestBytes, 0);
		byte [] sigBytes = Base64.getUrlDecoder().decode(sig);
		try {
			byte [] outsign = new TweetNaCl().crypto_sign_open(sigBytes, verifierKey.publicKey.getBytes());
			return Arrays.equals(digestBytes, outsign);
		}catch(InvalidSignatureException x){
			return false;
		}
	}
}
