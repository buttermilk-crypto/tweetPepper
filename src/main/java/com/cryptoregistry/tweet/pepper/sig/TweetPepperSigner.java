package com.cryptoregistry.tweet.pepper.sig;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map.Entry;

import com.cryptoregistry.digest.CubeHash256;
import com.cryptoregistry.digest.Digest;
import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.KMU;
import com.cryptoregistry.tweet.pepper.key.SigningKeyContents;
import com.cryptoregistry.tweet.salt.TweetNaCl;
import com.cryptoregistry.util.TimeUtil;

public class TweetPepperSigner {

	public final String signedBy;
	public final SigningKeyContents keyContents;
	public final List<Block> blocks;
	public final Digest digest;

	public TweetPepperSigner(String signedBy, SigningKeyContents keyContents) {
		super();
		this.signedBy = signedBy;
		this.keyContents = keyContents;
		blocks = new ArrayList<Block>();
		digest = new CubeHash256();
		if(signedBy == null) throw new RuntimeException("SignedBy field cannot be null");
	}
	
	public  TweetPepperSigner addBlock(Block block){
		blocks.add(block);
		return this;
	}
	
	public TweetPepperSigner addKMUBlocks(KMU kmu){
		for(String key: kmu.map.keySet()) {
			blocks.add(kmu.map.get(key));
		}
		
		return this;
	}
	
	public TweetPepperSignature sign(){
		
		TweetSignatureMetadata meta = new TweetSignatureMetadata(signedBy, keyContents.metadata.handle);
		Date signatureDateOfRecord = meta.createdOn;
		
		List<String> tokens = new ArrayList<String>();
		digest.reset();
		
		// top of digest is dateOfRecord, signedBy, signedWith. This means even an empty signature can be authenticated
		// dateOfRecord
		String sigDate = TimeUtil.format(signatureDateOfRecord);
		digest.update(sigDate.getBytes(StandardCharsets.UTF_8));
		tokens.add(meta.handle+"-S:"+"CreatedOn");
		
		// signedBy
		digest.update(signedBy.getBytes(StandardCharsets.UTF_8));
		tokens.add("."+"SignedBy");
		
		// signedWith
		digest.update(keyContents.metadata.handle.getBytes(StandardCharsets.UTF_8));
		tokens.add("."+"SignedWith");
		
		for(Block block: blocks){
			String uuid = block.name;
			boolean begin = true;
			for(Entry<String,String> entry: block.entrySet()) {
				String key = null;
				if(begin){
					key = uuid+":"+entry.getKey();
				}else{
					key = "."+entry.getKey();
				}
				String value = entry.getValue();
				tokens.add(key);
				digest.update(value.getBytes(StandardCharsets.UTF_8));
				begin = false;
			}
		}
		
		byte [] hash = digest.digest();
		byte [] signatureBytes = new TweetNaCl().crypto_sign(hash, keyContents.privateSigningKey.getBytes());
		
		
		return new TweetPepperSignature(meta, Base64.getUrlEncoder().encodeToString(signatureBytes), tokens);
	}

}
