package com.cryptoregistry.tweet.pepper.key;

import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.BlockType;
import com.cryptoregistry.util.TimeUtil;

public class SecretBoxKeyContents {

	TweetKeyMetadata metadata;
	SecretKey key;
	
	public SecretBoxKeyContents(TweetKeyMetadata metadata, SecretKey key) {
		super();
		this.metadata = metadata;
		this.key = key;
	}
	
	public Block toBlock() {
		Block b = new Block(BlockType.U);
		 b.put("KeyAlgorithm","TweetNaCl");
		 b.put("KeyUsage", metadata.keyUsage.toString());
		 b.put("CreatedOn",TimeUtil.format(this.metadata.createdOn));
         b.put("S", this.key.getEncoded());
         return b;
	}

}
