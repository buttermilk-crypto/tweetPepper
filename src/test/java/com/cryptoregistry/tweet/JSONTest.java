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

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.util.List;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.BlockType;
import com.cryptoregistry.tweet.pepper.KMU;
import com.cryptoregistry.tweet.pepper.TweetPepper;
import com.cryptoregistry.tweet.pepper.format.BlockFormatter;
import com.cryptoregistry.tweet.pepper.format.KMUInputAdapter;
import com.cryptoregistry.tweet.pepper.format.KMUOutputAdapter;
import com.cryptoregistry.tweet.pepper.key.BoxingKeyContents;
import com.cryptoregistry.tweet.pepper.key.SigningKeyContents;
import com.cryptoregistry.tweet.pepper.sig.TweetPepperSignature;
import com.cryptoregistry.tweet.pepper.sig.TweetPepperSigner;
import com.cryptoregistry.tweet.pepper.sig.TweetPepperVerifier;

public class JSONTest {

	@BeforeClass
	public static void warning() {
		System.err.println("These tests take some time to run. Don't be alarmed.");
	}
	
	
	@Test
	public void testBlockFormatting() {
		Block block = new Block(BlockType.D);
		block.put("Small", "a small value");
		block.put("Larger", "1111111111111111111111111111111111111112222222222222222222222222222222222222222222222223333333333333333333333333333333333444444444444444444444444444444444444555555555555555555555555555555555555666666666666666666666666666666666666666666");

		BoxingKeyContents key0 = new TweetPepper().generateBoxingKeys();
		Block keyBlock = key0.toBlock();
		
		BlockFormatter bf = new BlockFormatter();
		bf.addBlock(block)
			.addBlock(keyBlock);
		String json = bf.buildJSON().getJson();
		
		// round trip
		bf = new BlockFormatter(json);
		List<Block> outBlocks = bf.buildBlocks().getBlocks();
		Assert.assertTrue(block.equals(outBlocks.get(0)));
		Assert.assertTrue(keyBlock.equals(outBlocks.get(1)));
	}
	
	 @Test
	 public void writeKeys() {
	    	BoxingKeyContents key0 = new TweetPepper().generateBoxingKeys();
	    	SigningKeyContents key1 = new TweetPepper().generateSigningKeys();
	    	KMU confidential = new KMU("dave@cryptoregistry.com");
	    	confidential.addBlock(key0.toBlock());
	    	confidential.addBlock(key1.toBlock());
	    	char [] pass = {'p','a','s','s'};
	    	confidential.protectKeyBlocks(pass);
	    	KMUOutputAdapter kmuw = new KMUOutputAdapter(confidential);
	    	StringWriter keys = new StringWriter();
	    	kmuw.emitKeys(keys);
	    	Assert.assertNotNull(key0);
	    	Assert.assertNotNull(key1);
	    	System.err.println(keys.toString());
	    	
	 }
    
    @Test
    public void writeTransactionKMU() {
    	
    	SigningKeyContents sc = null;
    	BoxingKeyContents bc = null;
    	InputStream in = this.getClass().getResourceAsStream("/keys.json");
    	try (InputStreamReader reader = new InputStreamReader(in)){
    		KMUInputAdapter kmuReader = new KMUInputAdapter(reader);
    		KMU kmu = kmuReader.read();
    		char [] pass = {'p','a','s','s'};
    		kmu.openKeyBlocks(pass);
    		sc = kmu.getSigningKey();
    		bc = kmu.getBoxingKey();
    	} catch (IOException e) {
			e.printStackTrace();
			Assert.fail();
		}
    	
    	Block contactInfo = new Block(BlockType.C);
    	 contactInfo.put("ContactType","Person");
    	 contactInfo.put("GivenName.0","David");
    	 contactInfo.put("FamilyName.0","Smith");
    	 contactInfo.put("Email.0","dave@cryptoregistry.com");
    	 contactInfo.put("MobilePhone.0","+61449957431");
    	 contactInfo.put("TwitterHandle","Chinese_Knees");
    	 contactInfo.put("Country","AU");
    	Block affirmations = new Block(BlockType.D);
    	  affirmations.put("Copyright","Copyright 2016 by David R. Smith. All Rights Reserved");
    	  affirmations.put("TermsOfServiceAgreement",
    			  "I agree to cryptoregistry.com's Terms of Service");
    	  affirmations.put("InfoAffirmation",
    			  "I affirm the information I have entered in this file is valid and correct.");
    	  Block pubBoxing = bc.pubBlock();
    	  Block pubSigning = sc.pubBlock();
    	  
    	  KMU req = new KMU("dave@cryptoregistry.com");
      	  req.addBlock(contactInfo)
      	  .addBlock(affirmations)
      	  .addBlock(pubBoxing)
      	  .addBlock(pubSigning);
      	  
      	  TweetPepperSigner signer = new TweetPepperSigner("Chinese_Knees", sc);
      	  signer.addKMUBlocks(req);
      	  TweetPepperSignature sig = signer.sign();
      	  req.addBlock(sig.toBlock());
      	  
      	  KMUOutputAdapter kmur = new KMUOutputAdapter(req);
      	  StringWriter reqWriter = new StringWriter();
      	  kmur.writeTo(reqWriter);
      	  System.err.println(reqWriter.toString());
    }
    
    @Test
    public void readKMUKeys(){
    	
    	InputStream in = this.getClass().getResourceAsStream("/keys.json");
    	try (InputStreamReader reader = new InputStreamReader(in)){
    		KMUInputAdapter kmuReader = new KMUInputAdapter(reader);
    		KMU kmu = kmuReader.read();
    		Assert.assertEquals(2, kmu.map.size());
    		Assert.assertNotNull(kmu.map.get("3yW9H8jgN5yN5DoF4pCEFt-X"));
    		Assert.assertNotNull(kmu.map.get("2f18cpRAuoL5BKR0swGXaJ-X"));
    		
    		KMUOutputAdapter kwriter = new KMUOutputAdapter(kmu);
         	StringWriter reqWriter = new StringWriter();
         	kwriter.emitKeys(reqWriter);
         	String test = reqWriter.toString();
         	Assert.assertTrue(test.contains("3yW9H8jgN5yN5DoF4pCEFt-X"));
         	Assert.assertTrue(test.contains("2f18cpRAuoL5BKR0swGXaJ-X"));
    		
    		
    		char [] pass = {'p','a','s','s'};
    		kmu.openKeyBlocks(pass);
    		SigningKeyContents sc = kmu.getSigningKey();
    		BoxingKeyContents bc = kmu.getBoxingKey();
    		Assert.assertNotNull(sc);
    		Assert.assertNotNull(bc);
    		//Assert.assertTrue(bc.metadata.handle.equals("f8dff898-0e78-466b-90d7-ef125aab1d6d-U"));
    	//	Assert.assertTrue(sc.metadata.handle.equals("74cd46ce-cab9-403c-b3f6-61db1af3b518-U"));
    		
    	} catch (IOException e) {
			e.printStackTrace();
		}
    }
    
    @Test
    public void readKMUTransaction(){
    	InputStream in = this.getClass().getResourceAsStream("/reg-request.json");
    	try (InputStreamReader reader = new InputStreamReader(in)){
    		KMUInputAdapter kmuReader = new KMUInputAdapter(reader);
    		KMU kmu = kmuReader.read();
    		Assert.assertEquals(5, kmu.map.size());
    		
    		KMUOutputAdapter kwriter = new KMUOutputAdapter(kmu);
         	StringWriter reqWriter = new StringWriter();
         	kwriter.writeTo(reqWriter);
         	System.err.println(reqWriter.toString());
    		
    		
    	} catch (IOException e) {
			e.printStackTrace();
		}
    }
    
    @Test
    public void readKMUAndValidateSignature(){
    	InputStream in = this.getClass().getResourceAsStream("/reg-request.json");
    	try (InputStreamReader reader = new InputStreamReader(in)){
    		KMUInputAdapter kmuReader = new KMUInputAdapter(reader);
    		KMU kmu = kmuReader.read();
    		TweetPepperVerifier verifier = new TweetPepperVerifier();
    		verifier.addKMUBlocks(kmu);
    		if(!verifier.verify()){
    			Assert.fail();
    		}
    		
    	} catch (IOException e) {
			e.printStackTrace();
		}
    }
    
    
}
