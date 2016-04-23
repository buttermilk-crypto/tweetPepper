package com.cryptoregistry.tweet.pepper.key;

import java.util.Date;
import java.util.UUID;

import com.cryptoregistry.tweet.pepper.BlockType;

public class TweetKeyMetadata {

	public final String handle;
	public final BlockType blockType;
	public final Date createdOn;
	
	public TweetKeyMetadata(String handle, BlockType blockType, Date createdOn) {
		super();
		this.handle = handle;
		this.blockType = blockType;
		this.createdOn = createdOn;
	}

	public String toString() {
		return handle+"-"+blockType.toString();
	}
	
	public static TweetKeyMetadata createMetadata(BlockType t){
		return new TweetKeyMetadata(UUID.randomUUID().toString(), t, new Date());
	}

}
