package com.cryptoregistry.tweet.pepper.key;

public class SecretBoxKeyContents {

	TweetKeyMetadata metadata;
	SecretKey key;
	public SecretBoxKeyContents(TweetKeyMetadata metadata, SecretKey key) {
		super();
		this.metadata = metadata;
		this.key = key;
	}

}
