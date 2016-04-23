/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.tweet.pepper.key;

/**
 * used for secret box keys
 * 
 * @author Dave
 *
 */
public class SecretKey extends Key {

	public SecretKey(byte[] bytes) {
		super(bytes);
	}
	
	SecretKey(byte[] bytes,boolean alive) {
		super(bytes,alive);
	}

}
