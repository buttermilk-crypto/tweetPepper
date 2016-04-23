package com.cryptoregistry.tweet.pepper.key;

public class SigningKeyForPublication {
	
	public final PublicKey publicKey;
	public final TweetKeyMetadata metadata;
	
	public SigningKeyForPublication(PublicKey key, TweetKeyMetadata metadata) {
		super();
		this.publicKey = key;
		this.metadata = metadata;
	}

	

}
