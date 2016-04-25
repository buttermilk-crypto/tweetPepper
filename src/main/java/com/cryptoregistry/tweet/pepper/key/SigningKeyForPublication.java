package com.cryptoregistry.tweet.pepper.key;

import java.util.Base64;

import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.BlockType;
import com.cryptoregistry.util.TimeUtil;

public class SigningKeyForPublication {
	
	public final PublicKey publicKey;
	public final TweetKeyMetadata metadata;
	
	public SigningKeyForPublication(PublicKey key, TweetKeyMetadata metadata) {
		super();
		this.publicKey = key;
		this.metadata = metadata;
	}
	
	public SigningKeyForPublication(Block pubBlock){
		BlockType type = pubBlock.getBlockType();
		if(!type.equals(BlockType.P)) throw new RuntimeException("Not a -P block");
		String use = pubBlock.get("KeyUsage");
		String createdOn = pubBlock.get("CreatedOn");
		String P = pubBlock.get("P");
		metadata = 
				new TweetKeyMetadata(
					pubBlock.name, 
					BlockType.P, 
					TimeUtil.getISO8601FormatDate(createdOn), 
					KeyUsage.valueOf(use)
				);
		publicKey = new PublicKey(Base64.getUrlDecoder().decode(P));
		
	}

	public Block toBlock() {
		Block b = new Block(metadata.handle, BlockType.P);
		 b.put("KeyAlgorithm","TweetNaCl");
		 b.put("KeyUsage",metadata.keyUsage.toString());
		 b.put("CreatedOn",TimeUtil.format(this.metadata.createdOn));
         b.put("P", this.publicKey.getEncoded());
         return b;
	}

}
