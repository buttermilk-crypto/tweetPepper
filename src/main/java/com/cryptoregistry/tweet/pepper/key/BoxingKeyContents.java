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
package com.cryptoregistry.tweet.pepper.key;

import java.util.Base64;

import com.cryptoregistry.tweet.pepper.Block;

public class BoxingKeyContents extends BoxingKeyForPublication {
	
	public final PrivateKey secretBoxingKey;

	public BoxingKeyContents(TweetKeyMetadata metadata, PublicKey pubKey, PrivateKey privateBoxingKey) {
		super(pubKey, metadata);
		this.secretBoxingKey=privateBoxingKey;
	}
	
	public BoxingKeyContents(Block block){
		super(block);
		if(block.isU() && block.containsKey("S")&&block.containsKey("KeyUsage")&&block.get("KeyUsage").equals("Boxing")){
			this.secretBoxingKey= new PrivateKey(Base64.getUrlDecoder().decode(block.get("S")));
		}else{
			throw new RuntimeException("doesn't look like an open key block, or else KeyUsage is wrong");
		}
	}
	
	public Block toBlock() {
		 Block b = super.toBlock();
         b.put("S", this.secretBoxingKey.getEncoded());
         b.name = b.name.substring(0,b.name.length()-2)+"-U";
         return b;
	}
	
	public Block pubBlock() {
		 Block b = super.toBlock();
        return b;
	}

}
