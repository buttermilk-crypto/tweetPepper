package com.cryptoregistry.tweet;

import java.util.UUID;

import org.junit.Assert;
import org.junit.Test;

import com.cryptoregistry.tweet.url.BijectiveUUIDEncoder;
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
			BijectiveUUIDEncoder enc = new BijectiveUUIDEncoder();
			String val = enc.encode(uuid);
			System.err.println(val);
			UUID result = enc.decode(val);
			if(!uuid.equals(result)) {
				Assert.fail();
			}
		}
	}

}
