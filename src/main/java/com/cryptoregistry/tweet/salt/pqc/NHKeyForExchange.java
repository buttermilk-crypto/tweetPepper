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
package com.cryptoregistry.tweet.salt.pqc;

import java.util.Base64;

import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.BlockType;
import com.cryptoregistry.util.TimeUtil;

public class NHKeyForExchange {

	NHKeyMetadata metadata;
	final byte[] pubData;

	public NHKeyForExchange(byte[] pubData) {
		this.pubData = pubData;
		this.metadata = NHKeyMetadata.createMetadata(BlockType.A);
	}
	
	public Block toBlock() {
		Block b = new Block(metadata.handle, BlockType.A);
		 b.put("KeyAlgorithm","NewHope");
		 b.put("KeyUsage",metadata.keyUsage.toString());
		 b.put("CreatedOn",TimeUtil.format(this.metadata.createdOn));
         b.put("A", Base64.getUrlEncoder().encodeToString(pubData));
         return b;
	}

}
