package com.cryptoregistry.tweet;


import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;

import org.junit.Assert;
import org.junit.Test;

import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.BlockType;
import com.cryptoregistry.tweet.pepper.KMU;
import com.cryptoregistry.tweet.pepper.TweetPepper;
import com.cryptoregistry.tweet.pepper.format.KMUReader;
import com.cryptoregistry.tweet.pepper.format.KMUWriter;
import com.cryptoregistry.tweet.pepper.key.BoxingKeyContents;
import com.cryptoregistry.tweet.pepper.key.SigningKeyContents;
import com.cryptoregistry.tweet.pepper.sig.TweetPepperSignature;
import com.cryptoregistry.tweet.pepper.sig.TweetPepperSigner;
import com.cryptoregistry.tweet.pepper.sig.TweetPepperVerifier;

public class JSONTest {

	
	 @Test
	 public void writeKeys() {
	    	BoxingKeyContents key0 = TweetPepper.generateBoxingKeys();
	    	SigningKeyContents key1 = TweetPepper.generateSigningKeys();
	    	KMU confidential = new KMU("dave@cryptoregistry.com");
	    	confidential.addBlock(key0.toBlock());
	    	confidential.addBlock(key1.toBlock());
	    	char [] pass = {'p','a','s','s'};
	    	confidential.protectKeyBlocks(pass);
	    	KMUWriter kmuw = new KMUWriter(confidential);
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
    		KMUReader kmuReader = new KMUReader(reader);
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
      	  
      	  KMUWriter kmur = new KMUWriter(req);
      	  StringWriter reqWriter = new StringWriter();
      	  kmur.writeTo(reqWriter);
      	  System.err.println(reqWriter.toString());
    }
    
    @Test
    public void readKMUKeys(){
    	
    	InputStream in = this.getClass().getResourceAsStream("/keys.json");
    	try (InputStreamReader reader = new InputStreamReader(in)){
    		KMUReader kmuReader = new KMUReader(reader);
    		KMU kmu = kmuReader.read();
    		Assert.assertEquals(2, kmu.map.size());
    		Assert.assertNotNull(kmu.map.get("f8dff898-0e78-466b-90d7-ef125aab1d6d-X"));
    		Assert.assertNotNull(kmu.map.get("74cd46ce-cab9-403c-b3f6-61db1af3b518-X"));
    		
    		KMUWriter kwriter = new KMUWriter(kmu);
         	StringWriter reqWriter = new StringWriter();
         	kwriter.writeTo(reqWriter);
         	String test = reqWriter.toString();
         	Assert.assertTrue(test.contains("f8dff898-0e78-466b-90d7-ef125aab1d6d-X"));
         	Assert.assertTrue(test.contains("74cd46ce-cab9-403c-b3f6-61db1af3b518-X"));
    		
    		
    		char [] pass = {'p','a','s','s'};
    		kmu.openKeyBlocks(pass);
    		SigningKeyContents sc = kmu.getSigningKey();
    		BoxingKeyContents bc = kmu.getBoxingKey();
    		Assert.assertNotNull(sc);
    		Assert.assertNotNull(bc);
    		Assert.assertTrue(bc.metadata.handle.equals("f8dff898-0e78-466b-90d7-ef125aab1d6d-U"));
    		Assert.assertTrue(sc.metadata.handle.equals("74cd46ce-cab9-403c-b3f6-61db1af3b518-U"));
    		
    		
    		
    	} catch (IOException e) {
			e.printStackTrace();
		}
    }
    
    @Test
    public void readKMUTransaction(){
    	InputStream in = this.getClass().getResourceAsStream("/reg-request.json");
    	try (InputStreamReader reader = new InputStreamReader(in)){
    		KMUReader kmuReader = new KMUReader(reader);
    		KMU kmu = kmuReader.read();
    		Assert.assertEquals(5, kmu.map.size());
    		
    		KMUWriter kwriter = new KMUWriter(kmu);
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
    		KMUReader kmuReader = new KMUReader(reader);
    		KMU kmu = kmuReader.read();
    		TweetPepperVerifier verifier = new TweetPepperVerifier("Chinese_Knees");
    		verifier.addKMUBlocks(kmu);
    		if(!verifier.verify()){
    			Assert.fail();
    		}
    		
    	} catch (IOException e) {
			e.printStackTrace();
		}
    }
}
