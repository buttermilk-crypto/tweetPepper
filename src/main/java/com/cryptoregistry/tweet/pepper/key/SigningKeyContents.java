package com.cryptoregistry.tweet.pepper.key;

public class SigningKeyContents extends SigningKeyForPublication {
	
	public final PrivateKey privateSigningKey;

	public SigningKeyContents(TweetKeyMetadata metadata, PublicKey pubKey, PrivateKey privateSigningKey) {
		super(pubKey, metadata);
		this.privateSigningKey=privateSigningKey;
	}

}
