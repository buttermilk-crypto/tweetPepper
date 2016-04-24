package com.cryptoregistry.tweet.pepper.key;

import com.cryptoregistry.tweet.pepper.Block;

public class SigningKeyContents extends SigningKeyForPublication {
	
	public final PrivateKey privateSigningKey;

	public SigningKeyContents(TweetKeyMetadata metadata, PublicKey pubKey, PrivateKey privateSigningKey) {
		super(pubKey, metadata);
		this.privateSigningKey=privateSigningKey;
	}
	
	public Block toBlock() {
		 Block b = super.toBlock();
         b.put("S", this.privateSigningKey.getEncoded());
     	 b.name = b.name.substring(0,b.name.length()-2)+"-U";
         return b;
	}
	
	public Block pubBlock() {
		 Block b = super.toBlock();
       return b;
	}

}
