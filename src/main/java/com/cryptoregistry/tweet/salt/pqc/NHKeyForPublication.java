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
import com.cryptoregistry.tweet.pepper.key.KeyUsage;
import com.cryptoregistry.util.TimeUtil;

public class NHKeyForPublication {

	final NHKeyMetadata metadata;
	final byte[] pubData;
	
	public NHKeyForPublication(NHKeyMetadata metadata, byte[] pubData) {
		this.metadata = metadata;
		this.pubData = pubData;
	}

	// For Pub key
	public NHKeyForPublication(byte[] pubData) {
		this.pubData = pubData;
		this.metadata = NHKeyMetadata.createMetadata(BlockType.P);
	}
	
	public NHKeyForPublication(Block pubBlock){
		BlockType type = pubBlock.getBlockType();
		String use = pubBlock.get("KeyUsage");
		String createdOn = pubBlock.get("CreatedOn");
		String P = pubBlock.get("P");
		metadata = 
				new NHKeyMetadata(
					pubBlock.name.substring(0,pubBlock.name.length()-2), 
					type, 
					TimeUtil.getISO8601FormatDate(createdOn), 
					KeyUsage.valueOf(use)
				);
		pubData = Base64.getUrlDecoder().decode(P);
		
	}

	public NHKeyMetadata getMetadata() {
		return metadata;
	}

	public byte[] getPubData() {
		return pubData;
	}
	
	public Block toBlock() {
		Block b = new Block(metadata.handle, BlockType.P);
		 b.put("KeyAlgorithm","NewHope");
		 b.put("KeyUsage",metadata.keyUsage.toString());
		 b.put("CreatedOn",TimeUtil.format(this.metadata.createdOn));
         b.put("P", Base64.getUrlEncoder().encodeToString(pubData));
         return b;
	}

}
