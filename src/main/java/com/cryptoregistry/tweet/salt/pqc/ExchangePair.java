/*
 
Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
Copyright 2016, David R. Smith, All Rights Reserved

This file is part of TweetPepper.

TweetPepper is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

TweetPepper is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TweetPepper.  If not, see <http://www.gnu.org/licenses/>.

 */
package com.cryptoregistry.tweet.salt.pqc;

/**
 * Pair for a value exchange algorithm where the responding party has no private
 * key, such as NewHope.
 */
public class ExchangePair {
	private final NHKeyForExchange publicKey;
	private final byte[] shared;

	/**
	 * Base constructor.
	 *
	 * @param publicKey
	 *            The responding party's public key.
	 * @param shared
	 *            the calculated shared value.
	 */
	public ExchangePair(NHKeyForExchange forExchange, byte[] shared) {
		this.publicKey = forExchange;
		this.shared = shared;
	}

	/**
	 * Return the responding party's public key.
	 *
	 * @return the public key calculated for the exchange.
	 */
	public NHKeyForExchange getPublicKey() {
		return publicKey;
	}

	/**
	 * Return the shared value calculated with public key.
	 *
	 * @return the shared value.
	 */
	public byte[] getSharedValue() {
		return shared;
	}
}
