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
import com.cryptoregistry.tweet.pepper.BlockType;
import com.cryptoregistry.util.TimeUtil;

public class BoxingKeyForPublication {
	
	public final PublicKey publicKey;
	public final TweetKeyMetadata metadata;
	
	public BoxingKeyForPublication(PublicKey key, TweetKeyMetadata metadata) {
		super();
		this.publicKey = key;
		this.metadata = metadata;
	}
	
	public BoxingKeyForPublication(Block pubBlock){
		BlockType type = pubBlock.getBlockType();
		//if(!type.equals(BlockType.P)) throw new RuntimeException("Not a -P block");
		String use = pubBlock.get("KeyUsage");
		String createdOn = pubBlock.get("CreatedOn");
		String P = pubBlock.get("P");
		metadata = 
				new TweetKeyMetadata(
					pubBlock.name.substring(0,pubBlock.name.length()-2), 
					type, 
					TimeUtil.getISO8601FormatDate(createdOn), 
					KeyUsage.valueOf(use)
				);
		publicKey = new PublicKey(Base64.getUrlDecoder().decode(P));
		
	}
	
	public Block toBlock() {
		Block b = new Block(metadata.handle, BlockType.P);
		 b.put("KeyAlgorithm","TweetNaCl");
		 b.put("KeyUsage",metadata.keyUsage.toString());
		 b.put("CreatedOn",TimeUtil.format(this.metadata.createdOn));
         b.put("P", this.publicKey.getEncoded());
         return b;
	}

}
