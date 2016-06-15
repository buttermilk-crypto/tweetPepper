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

import java.io.StringReader;
import java.io.StringWriter;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.KMU;
import com.cryptoregistry.tweet.pepper.TweetPepper;
import com.cryptoregistry.tweet.pepper.format.KMUInputAdapter;
import com.cryptoregistry.tweet.pepper.format.KMUOutputAdapter;
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
	
	@Test
	public void test1() {
		
		// step 1 - Alice generates a key pair
		TweetPepper tpA = new TweetPepper();
		NHKeyContents contentsAlice = tpA.generatePQCKeys();
		NHKeyForPublication pubAlice = contentsAlice.getPublicKey();
		
		// step 2, save alice's keys into a protected format
		Block contentsBlock = contentsAlice.toBlock();
		KMU kmu = new KMU(contentsBlock);
		char [] pass = {'p','a','s','s'};
		kmu.protectKeyBlocks(pass);
		StringWriter out = new StringWriter();
		KMUOutputAdapter outAdapter = new KMUOutputAdapter(kmu);
		outAdapter.emitKeys(out);
		System.err.println(out.toString()); // save the out to file
		
		// step 3, alice send pub key to bob
		Block pubBlock = pubAlice.toBlock();
		kmu = new KMU("AliceMac", "alice@cryptoregistry.com");
		kmu.addBlock(pubBlock);
		outAdapter = new KMUOutputAdapter(kmu);
		out = new StringWriter();
		outAdapter.writeTo(out);
		System.err.println(out.toString()); // save the out to file and send to Bob
		
		// step 4, Bob prepares an exchange pair for exchange with Alice based on her pub key
		StringReader reader = new StringReader(out.toString());
		KMUInputAdapter in = new KMUInputAdapter(reader);
		KMU alicePubKMU = in.read();
		TweetPepper tpB = new TweetPepper();
		ExchangePair bobExchangePair = tpB.generateExchange(alicePubKMU.getNewHopePubKey());
		
		// step 5 this produces the shared secret for Bob and an exchange key to send to Alice:
		byte [] bobSharedSecret = bobExchangePair.getSharedValue();
		NHKeyForExchange bobKeyForExchange = bobExchangePair.getPublicKey();
		
		// step 6, bob send key for exchange to alice
		
		// step 7, Alice calculates her shared secret using her private key contents and Bob's exchange key
		byte [] aliceSharedSecret = tpA.calculateAgreement(contentsAlice, bobKeyForExchange);
		
		Assert.assertTrue(Arrays.equals(aliceSharedSecret, bobSharedSecret));
		
	}

}
