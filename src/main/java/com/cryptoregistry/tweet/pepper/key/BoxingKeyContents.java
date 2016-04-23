package com.cryptoregistry.tweet.pepper.key;

public class BoxingKeyContents extends BoxingKeyForPublication {
	
	public final PrivateKey privateBoxingKey;

	public BoxingKeyContents(TweetKeyMetadata metadata, PublicKey pubKey, PrivateKey privateBoxingKey) {
		super(pubKey, metadata);
		this.privateBoxingKey=privateBoxingKey;
	}

}
