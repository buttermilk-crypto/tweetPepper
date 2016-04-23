/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.tweet.pepper;

import java.util.Date;
import java.util.UUID;

public class TweetSignatureMetadata {
	
	public static final String defaultDigestAlg ="SHA-224";

	public final String handle; 
	public final Date createdOn; 
	public final String digestAlg; 
	public final String signedWith; 
	public final String signedBy;
	
	// a list of string values to anything, usually handles referenced in the signature, or a brief note -
	// normally not part of the signature, advisory only
	public String apropos;

	public TweetSignatureMetadata(String handle, Date createdOn, String digestAlg, String signedWith,
			String signedBy) {
		super();
		this.handle = handle;
		this.createdOn = createdOn;
		this.digestAlg = digestAlg;
		this.signedWith = signedWith;
		this.signedBy = signedBy;
	}

	public TweetSignatureMetadata(String hashAlg, String signedWith,String signedBy){
		this(UUID.randomUUID().toString(),new Date(),hashAlg,signedWith,signedBy);
	}
	
	public TweetSignatureMetadata(String signedWith,String signedBy){
		this(UUID.randomUUID().toString(),new Date(),defaultDigestAlg,signedWith,signedBy);
	}
	

	@Override
	public String toString() {
		return handle+"-S";
	}

}
