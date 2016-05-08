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

package com.cryptoregistry.tweet.pepper.sig;

import java.util.Date;
import java.util.UUID;

import com.cryptoregistry.tweet.url.BijectiveEncoder;

public class TweetSignatureMetadata {
	
	public static final String defaultDigestAlg ="CubeHash-256";

	public final String handle; 
	public final Date createdOn; 
	public final String digestAlg; 
	public final String signedWith; 
	public final String signedBy;
	
	// a list of string values to anything, usually handles referenced in the signature, or a brief note -
	// normally not part of the signature, advisory only
	public String apropos;

	public TweetSignatureMetadata(String base, Date createdOn, String digestAlg, String signedWith,
			String signedBy) {
		super();
		this.handle = base;
		this.createdOn = createdOn;
		this.digestAlg = digestAlg;
		this.signedWith = signedWith;
		this.signedBy = signedBy;
	}

	public TweetSignatureMetadata(String hashAlg, String signedBy,String signedWith){
		
		this(new BijectiveEncoder().encode(UUID.randomUUID()),new Date(),hashAlg,signedWith,signedBy);
	}
	
	public TweetSignatureMetadata(String signedBy,String signedWith){
		this(new BijectiveEncoder().encode(UUID.randomUUID()),new Date(),defaultDigestAlg,signedWith,signedBy);
	}
	

	@Override
	public String toString() {
		return handle+"-S";
	}

}
