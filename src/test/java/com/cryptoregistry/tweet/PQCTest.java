/*
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
package com.cryptoregistry.tweet;

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

import com.cryptoregistry.tweet.pepper.TweetPepper;
import com.cryptoregistry.tweet.salt.pqc.ExchangePair;
import com.cryptoregistry.tweet.salt.pqc.NHKeyContents;
import com.cryptoregistry.tweet.salt.pqc.NHKeyForExchange;
import com.cryptoregistry.tweet.salt.pqc.NHKeyForPublication;

public class PQCTest {

	@Test
	public void test0() {
		
		// step 1 - Alice generates a key pair
		TweetPepper tpA = new TweetPepper();
		NHKeyContents contentsAlice = tpA.generatePQCKeys();
		NHKeyForPublication pubAlice = contentsAlice.getPublicKey();
		
		// step 2, Bob prepares an exchange pair for exchange with Alice based on her pubkey
		TweetPepper tpB = new TweetPepper();
		ExchangePair bobExchangePair = tpB.generateExchange(pubAlice);
		
		// this produces the shared secret for Bob and an exchange key to send to Alice:
		byte [] bobSharedSecret = bobExchangePair.getSharedValue();
		NHKeyForExchange bobKeyForExchange = bobExchangePair.getPublicKey();
		
		
		// meanwhile, Alice calculates her shared secret using her private key contents and Bob's exchange key
		byte [] aliceSharedSecret = tpA.calculateAgreement(contentsAlice, bobKeyForExchange);
		
		
		Assert.assertTrue(Arrays.equals(aliceSharedSecret, bobSharedSecret));
		
	}

}
