/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.tweet.pepper.key;

public class PrivateKey extends Key {

	public PrivateKey(byte[] bytes) {
		super(bytes);
	}

	PrivateKey(byte[] bytes,boolean alive) {
		super(bytes,alive);
	}

}
