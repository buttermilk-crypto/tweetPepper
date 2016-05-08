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

import java.util.List;

import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.BlockType;
import com.cryptoregistry.util.TimeUtil;

public class TweetPepperSignature {

	public final TweetSignatureMetadata metadata;
	public final String signature; // base64url encoded
	public final List<String> tokens;
	
	public TweetPepperSignature(TweetSignatureMetadata metadata, String signature, List<String> tokens) {
		super();
		this.metadata = metadata;
		this.signature = signature;
		this.tokens = tokens;
	}
	
	public Block toBlock() {
		Block b = new Block(metadata.handle, BlockType.S);
		b.put("CreatedOn",TimeUtil.format(this.metadata.createdOn));
        b.put("DigestAlgorithm", this.metadata.digestAlg);
        b.put("SignedWith", this.metadata.signedWith);
        b.put("SignedBy", this.metadata.signedBy);
        b.put("s", signature);
        b.put("DataRefs", listToString());
		return b;
	}
	
	private String listToString() {
		StringBuffer buf = new StringBuffer();
		for(String token: tokens){
			buf.append(token);
			buf.append(", ");
		}
		buf.delete(buf.length()-2, buf.length());
		return buf.toString();
	}
	
}
