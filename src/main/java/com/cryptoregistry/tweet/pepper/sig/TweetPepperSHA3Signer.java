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
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map.Entry;

import com.cryptoregistry.digest.sha3.SHA3Digest;
import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.KMU;
import com.cryptoregistry.tweet.pepper.key.SigningKeyContents;
import com.cryptoregistry.tweet.salt.TweetNaCl;
import com.cryptoregistry.util.TimeUtil;

public class TweetPepperSHA3Signer {

	public final String signedBy;
	public final SigningKeyContents keyContents;
	public final List<Block> blocks;
	public final SHA3Digest digest;

	public TweetPepperSHA3Signer(String signedBy, SigningKeyContents keyContents) {
		super();
		this.signedBy = signedBy;
		this.keyContents = keyContents;
		blocks = new ArrayList<Block>();
		digest = new SHA3Digest();
		if(signedBy == null) throw new RuntimeException("SignedBy field cannot be null");
	}
	
	public  TweetPepperSHA3Signer addBlock(Block block){
		blocks.add(block);
		return this;
	}
	
	public TweetPepperSHA3Signer addKMUBlocks(KMU kmu){
		for(String key: kmu.map.keySet()) {
			blocks.add(kmu.map.get(key));
		}
		
		return this;
	}
	
	public TweetPepperSignature sign(){
		
		TweetSignatureMetadata meta = new TweetSignatureMetadata("SHA3", signedBy, keyContents.metadata.handle);
		Date signatureDateOfRecord = meta.createdOn;
		
		List<String> tokens = new ArrayList<String>();
		digest.reset();
		
		// top of digest is dateOfRecord, signedBy, signedWith. This means even an empty signature can be authenticated
		// dateOfRecord
		String sigDate = TimeUtil.format(signatureDateOfRecord);
		byte [] bytes = sigDate.getBytes(StandardCharsets.UTF_8);
		digest.update(bytes, 0,bytes.length);
		tokens.add(meta.handle+"-S:"+"CreatedOn");
		
		// signedBy
		bytes = signedBy.getBytes(StandardCharsets.UTF_8);
		digest.update(bytes,0, bytes.length);
		tokens.add("."+"SignedBy");
		
		// signedWith
		bytes = keyContents.metadata.handle.getBytes(StandardCharsets.UTF_8);
		digest.update(bytes, 0, bytes.length);
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
				bytes = value.getBytes(StandardCharsets.UTF_8);
				digest.update(bytes, 0, bytes.length);
				begin = false;
			}
		}
		
		byte [] hash = new byte [digest.getDigestSize()];
		digest.doFinal(hash, 0);
		byte [] signatureBytes = new TweetNaCl().crypto_sign(hash, keyContents.privateSigningKey.getBytes());
		
		
		return new TweetPepperSignature(meta, Base64.getUrlEncoder().encodeToString(signatureBytes), tokens);
	}

}
