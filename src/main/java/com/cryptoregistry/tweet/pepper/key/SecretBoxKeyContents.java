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

import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.BlockType;
import com.cryptoregistry.util.TimeUtil;

public class SecretBoxKeyContents {

	TweetKeyMetadata metadata;
	SecretKey key;
	
	public SecretBoxKeyContents(TweetKeyMetadata metadata, SecretKey key) {
		super();
		this.metadata = metadata;
		this.key = key;
	}
	
	public Block toBlock() {
		Block b = new Block(BlockType.U);
		 b.put("KeyAlgorithm","TweetNaCl");
		 b.put("KeyUsage", metadata.keyUsage.toString());
		 b.put("CreatedOn",TimeUtil.format(this.metadata.createdOn));
         b.put("S", this.key.getEncoded());
         return b;
	}

}
