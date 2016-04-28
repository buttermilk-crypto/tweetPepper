package com.cryptoregistry.tweet;


import org.junit.Assert;
import org.junit.Test;

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

}
