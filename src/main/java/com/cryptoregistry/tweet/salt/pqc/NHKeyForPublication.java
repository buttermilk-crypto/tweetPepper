package com.cryptoregistry.tweet.salt.pqc;

public class NHKeyForPublication {

	NHKeyMetadata metadata;
	final byte[] pubData;

	public NHKeyForPublication(byte[] pubData) {
		this.pubData = pubData;
	}

}
