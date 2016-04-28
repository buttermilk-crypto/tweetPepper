package com.cryptoregistry.tweet.pepper.sig;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.cryptoregistry.digest.CubeHash224;
import com.cryptoregistry.digest.CubeHash256;
import com.cryptoregistry.digest.CubeHash384;
import com.cryptoregistry.digest.CubeHash512;
import com.cryptoregistry.digest.Digest;
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
	
	protected final String signedBy;
	protected final List<Block> blocks;

	public TweetPepperVerifier(String signedBy) {
		this.signedBy = signedBy;
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
		final String signedBy = sigBlock.get("SignedBy");
		final String digestAlgorithm = sigBlock.get("DigestAlgorithm");
		final String sig = sigBlock.get("s");
		final String dataRefs = sigBlock.get("DataRefs");
		final String signatureDateOfRecord = sigBlock.get("CreateOn");
		
		// 1.2 - now locate the for-publication block (must be a signing key) and rehydrate the key
		
		Block keyBlock = null;
		for(Block b: blocks){
			if(b.name.endsWith("-P") && b.name.startsWith(signedWith)){
				keyBlock = b;
				break;
			}
		}
		
		if(keyBlock == null) throw new RuntimeException("Could not find a suitable signing public key");
		
		SigningKeyForPublication verifierKey = new SigningKeyForPublication(keyBlock);
		
		
		// 1.3 - create the appropriate Digest object
		Digest digest = null;
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
		// this is the signature's available validation scope
		
		Map<String,String> scope = new HashMap<String,String>();
		for(Block block: blocks){
			block.loadToSignatureScope(scope);
		}
		
		// 1.5.0 - digesting. The first items are always the signature's CreatedOn, SignedBy and SignedWith fields
		digest.update(signatureDateOfRecord.getBytes(StandardCharsets.UTF_8));
		digest.update(signedBy.getBytes(StandardCharsets.UTF_8));
		digest.update(signedWith.getBytes(StandardCharsets.UTF_8));
		
		// 1.5.1 - run a loop on the data ref list. It will be normalized in the pass.
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
			if(value == null) throw new RuntimeException("Missing value in scope map");
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
}
