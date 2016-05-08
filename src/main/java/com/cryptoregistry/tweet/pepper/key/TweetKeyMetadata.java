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

import java.util.Date;
import java.util.UUID;

import com.cryptoregistry.tweet.pepper.BlockType;

public class TweetKeyMetadata {

	public final String handle;
	public final BlockType blockType;
	public final Date createdOn;
	public final KeyUsage keyUsage;
	
	public TweetKeyMetadata(String handle, BlockType blockType, Date createdOn, KeyUsage keyUsage) {
		super();
		this.handle = handle;
		this.blockType = blockType;
		this.createdOn = createdOn;
		this.keyUsage = keyUsage;
	}

	public String toString() {
		return handle+"-"+blockType.toString();
	}
	
	public static TweetKeyMetadata createSigningMetadata(BlockType t){
		return new TweetKeyMetadata(UUID.randomUUID().toString(), t, new Date(),KeyUsage.Signing);
	}
	
	public static TweetKeyMetadata createBoxingMetadata(BlockType t){
		return new TweetKeyMetadata(UUID.randomUUID().toString(), t, new Date(),KeyUsage.Boxing);
	}
	
	public static TweetKeyMetadata createSecretBoxMetadata(BlockType t){
		return new TweetKeyMetadata(UUID.randomUUID().toString(), t, new Date(),KeyUsage.SecretBox);
	}

}
