package com.cryptoregistry.tweet.salt.pqc;

public class NHKeyContents extends NHKeyForPublication {

	final short[] secData;

	public NHKeyContents(byte[] pubData, short[] secData) {
		super(pubData);
		this.secData = secData;

	}

}
