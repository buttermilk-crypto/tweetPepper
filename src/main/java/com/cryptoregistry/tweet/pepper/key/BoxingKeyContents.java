package com.cryptoregistry.tweet.pepper.key;

import java.util.Base64;

import com.cryptoregistry.tweet.pepper.Block;

public class BoxingKeyContents extends BoxingKeyForPublication {
	
	public final PrivateKey secretBoxingKey;

	public BoxingKeyContents(TweetKeyMetadata metadata, PublicKey pubKey, PrivateKey privateBoxingKey) {
		super(pubKey, metadata);
		this.secretBoxingKey=privateBoxingKey;
	}
	
	public BoxingKeyContents(Block block){
		super(block);
		if(block.isU() && block.containsKey("S")&&block.containsKey("KeyUsage")&&block.get("KeyUsage").equals("Boxing")){
			this.secretBoxingKey= new PrivateKey(Base64.getUrlDecoder().decode(block.get("S")));
		}else{
			throw new RuntimeException("doesn't look like an open key block, or else KeyUsage is wrong");
		}
	}
	
	public Block toBlock() {
		 Block b = super.toBlock();
         b.put("S", this.secretBoxingKey.getEncoded());
         b.name = b.name.substring(0,b.name.length()-2)+"-U";
         return b;
	}
	
	public Block pubBlock() {
		 Block b = super.toBlock();
        return b;
	}

}
