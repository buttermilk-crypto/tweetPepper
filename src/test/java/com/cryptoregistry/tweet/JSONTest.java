package com.cryptoregistry.tweet;


import java.io.InputStream;
import java.io.StringWriter;

import org.junit.Test;

import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.BlockType;
import com.cryptoregistry.tweet.pepper.KMU;
import com.cryptoregistry.tweet.pepper.TweetPepper;
import com.cryptoregistry.tweet.pepper.format.KMUWriter;
import com.cryptoregistry.tweet.pepper.key.BoxingKeyContents;
import com.cryptoregistry.tweet.pepper.key.SigningKeyContents;

public class JSONTest {

    @Test
    public void parseJson() {
      
    	InputStream in = this.getClass().getResourceAsStream("/chinese-eyes.json");
 
    }
    
    @Test
    public void writeKMU() {
    	BoxingKeyContents key0 = TweetPepper.generateBoxingKeys();
    	SigningKeyContents key1 = TweetPepper.generateSigningKeys();
    	KMU confidential = new KMU("dave@cryptoregistry.com");
    	confidential.addBlock(key0.toBlock());
    	confidential.addBlock(key1.toBlock());
    	KMUWriter kmuw = new KMUWriter(confidential);
    	StringWriter keys = new StringWriter();
    	kmuw.emitKeys(keys);
    	System.err.println(keys.toString());
    	
    	Block contactInfo = new Block(BlockType.C);
    	 contactInfo.put("contactType","Person");
    	 contactInfo.put("GivenName.0","Dave");
    	 contactInfo.put("FamilyName.0","Smith");
    	 contactInfo.put("Email.0","davesmith.gbs@gmail.com");
    	 contactInfo.put("MobilePhone.0","+61449957431");
    	 contactInfo.put("Country","AU");
    	Block affirmations = new Block(BlockType.D);
    	  affirmations.put("Copyright","Copyright 2016 by David R. Smith. All Rights Reserved");
    	  affirmations.put("TermsOfServiceAgreement",
    			  "I agree to cryptoregistry.com's Terms of Service");
    	  affirmations.put("InfoAffirmation",
    			  "I affirm the information I have entered in this file is valid and correct.");
    	  Block pubBoxing = key0.pubBlock();
    	  Block pubSigning = key1.pubBlock();
    	  
    	  KMU req = new KMU("dave@cryptoregistry.com");
      	  req.addBlock(contactInfo)
      	  .addBlock(affirmations)
      	  .addBlock(pubBoxing)
      	  .addBlock(pubSigning);
      	  KMUWriter kmur = new KMUWriter(req);
      	  StringWriter reqWriter = new StringWriter();
      	  kmur.writeTo(reqWriter);
      	  System.err.println(reqWriter.toString());
    	
    }
}
