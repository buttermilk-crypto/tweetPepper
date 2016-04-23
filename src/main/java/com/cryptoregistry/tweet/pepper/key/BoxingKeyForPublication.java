package com.cryptoregistry.tweet.pepper.key;

import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.BlockType;
import com.cryptoregistry.util.TimeUtil;

public class BoxingKeyForPublication {
	
	public final PublicKey publicKey;
	public final TweetKeyMetadata metadata;
	
	public BoxingKeyForPublication(PublicKey key, TweetKeyMetadata metadata) {
		super();
		this.publicKey = key;
		this.metadata = metadata;
	}
	
	public Block toBlock() {
		Block b = new Block(BlockType.U);
		 b.put("KeyAlgorithm","TweetNaCl");
		 b.put("KeyUsage",KeyUsage.Boxing.toString());
		 b.put("CreatedOn",TimeUtil.format(this.metadata.createdOn));
         b.put("P", this.publicKey.getEncoded());
         return b;
	}

}
