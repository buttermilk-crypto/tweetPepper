package com.cryptoregistry.tweet.pepper.key;

import java.util.Date;
import java.util.UUID;

import com.cryptoregistry.tweet.pepper.BlockType;

public class TweetKeyMetadata {

	public final String handle;
	public final BlockType blockType;
	public final Date createdOn;
	public final KeyUsage keyUsage;
	
	public TweetKeyMetadata(String handle, BlockType blockType, Date createdOn, KeyUsage keyUsage) {
		super();
		this.handle = handle;
		this.blockType = blockType;
		this.createdOn = createdOn;
		this.keyUsage = keyUsage;
	}

	public String toString() {
		return handle+"-"+blockType.toString();
	}
	
	public static TweetKeyMetadata createSigningMetadata(BlockType t){
		return new TweetKeyMetadata(UUID.randomUUID().toString(), t, new Date(),KeyUsage.Signing);
	}
	
	public static TweetKeyMetadata createBoxingMetadata(BlockType t){
		return new TweetKeyMetadata(UUID.randomUUID().toString(), t, new Date(),KeyUsage.Boxing);
	}
	
	public static TweetKeyMetadata createSecretBoxMetadata(BlockType t){
		return new TweetKeyMetadata(UUID.randomUUID().toString(), t, new Date(),KeyUsage.SecretBox);
	}

}