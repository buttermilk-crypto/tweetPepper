package com.cryptoregistry.tweet.pepper.key;

public class BoxingKeyForPublication {
	
	public final PublicKey publicKey;
	public final TweetKeyMetadata metadata;
	
	public BoxingKeyForPublication(PublicKey key, TweetKeyMetadata metadata) {
		super();
		this.publicKey = key;
		this.metadata = metadata;
	}

	

}
