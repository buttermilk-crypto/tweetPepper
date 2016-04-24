package com.cryptoregistry.tweet.pepper.key;

import com.cryptoregistry.tweet.pepper.Block;

public class BoxingKeyContents extends BoxingKeyForPublication {
	
	public final PrivateKey privateBoxingKey;

	public BoxingKeyContents(TweetKeyMetadata metadata, PublicKey pubKey, PrivateKey privateBoxingKey) {
		super(pubKey, metadata);
		this.privateBoxingKey=privateBoxingKey;
	}
	
	public Block toBlock() {
		 Block b = super.toBlock();
         b.put("S", this.privateBoxingKey.getEncoded());
         return b;
	}
	
	public Block pubBlock() {
		 Block b = super.toBlock();
        return b;
	}

}
