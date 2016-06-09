package com.cryptoregistry.tweet;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.junit.Assert;
import org.junit.Test;

import com.cryptoregistry.tweet.pepper.KMU;
import com.cryptoregistry.tweet.pepper.format.KMUInputAdapter;
import com.cryptoregistry.tweet.pepper.format.img.Constants;
import com.cryptoregistry.tweet.pepper.format.img.PNGSignatureVerifier;
import com.cryptoregistry.tweet.pepper.format.img.PNGSigner;
import com.cryptoregistry.tweet.pepper.format.img.PNGWrapperGenerator;
import com.cryptoregistry.tweet.pepper.format.img.PNGWrapperSpec;
import com.cryptoregistry.tweet.pepper.key.SigningKeyContents;

public class PNGTest {
	
	@Test
	public void test1(){
		class T extends Constants{
			final byte [] val = {0x00, 0x00, 0x00, 0x0D};
			final byte [] val2 = {0x00, 0x00,(byte) 0x80, 0x00};
			void test(){
				long res = uint(val);
				Assert.assertEquals(13, res);
				res=uint(val2);
				Assert.assertEquals(32768, res);
			}
		}
		
		T t = new T();
		t.test();
		
	}

	@Test
	public void test0() {
		
		String path = "target/data/test.png";
		KMU kmu = null;
		InputStream in = this.getClass().getResourceAsStream("/reg-request.json");
		
    	try (InputStreamReader reader = new InputStreamReader(in)){
    		
    		KMUInputAdapter kmuReader = new KMUInputAdapter(reader);
    		kmu = kmuReader.read();
    		
    		PNGWrapperSpec spec = new PNGWrapperSpec();
    		spec.put("output.path", path);
    		spec.put("twitter.handle", "Chinese_Knees");
    		PNGWrapperGenerator formatter = new PNGWrapperGenerator(spec,kmu);
    		formatter.write();
    		
    	} catch (IOException e) {
    		Assert.fail(e.getMessage());
		}
    	
    	// embed kmu and sign
    	in = this.getClass().getResourceAsStream("/keys.json");
    	try (InputStreamReader reader = new InputStreamReader(in)){
    		
    		KMUInputAdapter kmuReader = new KMUInputAdapter(reader);
    		KMU signerKeys = kmuReader.read();
    		
    		char [] pass = {'p','a','s','s'};
    		signerKeys.openKeyBlocks(pass);
    		SigningKeyContents sc = signerKeys.getSigningKey();
    		Assert.assertNotNull(sc);
    		
    		PNGSigner signer = new PNGSigner("Chinese_Knees", "dave@cryptoregistry.com", sc);
    		signer.signAndWrap(new File(path), kmu);
    		
    	} catch (IOException e) {
    		Assert.fail(e.getMessage());
		}
    	
    	File infile = new File(path);
		FileInputStream stream;
		try {
			stream = new FileInputStream(infile);
			PNGSignatureVerifier verifier = new PNGSignatureVerifier(stream,true);
			Assert.assertTrue(verifier.verify());
			KMU _kmu = verifier.getKeyStore();
			Assert.assertTrue(kmu.equals(_kmu));
		} catch (IOException e) {
    		Assert.fail(e.getMessage());
		}
    	
    	
	}

}
