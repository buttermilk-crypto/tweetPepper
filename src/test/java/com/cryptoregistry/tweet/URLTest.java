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

import java.util.UUID;

import org.junit.Assert;
import org.junit.Test;

import com.cryptoregistry.tweet.url.BijectiveEncoder;
import com.cryptoregistry.tweet.url.ShortID;

public class URLTest {

	@Test
	public void test0() {
		int initial = 1234567890;
		ShortID s = new ShortID();
		String encoded = s.encode(initial);
		
		int val = s.decode(encoded);
		Assert.assertTrue(initial == val);
	}
	
	@Test
	public void test1() {
		for(int i = 0; i<1000;i++){
			UUID uuid = UUID.randomUUID();
			BijectiveEncoder enc = new BijectiveEncoder();
			String val = enc.encode(uuid);
			System.err.println(val);
			UUID result = enc.decode(val);
			if(!uuid.equals(result)) {
				Assert.fail();
			}
		}
	}

}
