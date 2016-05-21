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

package com.cryptoregistry.tweet.pepper.format;

import java.io.IOException;
import java.io.Reader;

import java.util.List;

import com.cryptoregistry.json.Json;
import com.cryptoregistry.json.JsonObject;
import com.cryptoregistry.json.JsonValue;
import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.BlockType;
import com.cryptoregistry.tweet.pepper.KMU;

/**
 * Read a JSON file and build a KMU or "Key Material Unit" object. A KMU is logically similar in function 
 * to a key store but has more flexibility (e.g., can contain arbitrary data, contacts, etc). It is more like a
 * message in some ways and less like a data store, which is what a key store reminds me of.
 * 
 * @author Dave
 *
 */
public class KMUInputAdapter {
	
	private KMU kmu;
	private final Reader in;
	private final BlockFormatter bf;

	public KMUInputAdapter(Reader in) {
		this.in = in;
		bf = new BlockFormatter();
	}
	
	public KMU read(){
	
		try {
			JsonValue root = Json.parse(in);
			JsonObject obj = root.asObject();
			String version = obj.get("Version").asString(); //all Tweet formats have a version
			switch(version){
				case "Buttermilk Tweet Pepper Keys 1.0": {
					kmu = new KMU();
					// we expect an arbitrary number of keys (-X) or -U as the Contents but other 
					// types are not omitted if exist
					JsonObject contents = obj.get("Contents").asObject();
					kmu.addBlocks(bf.fromJsonObject(contents).getBlocks());
					
					break;
				}
				case "Buttermilk Tweet Pepper 1.0" : {
					// would not contain -X or -U, as these confidential bits should not be exported
					// but would contain KMUHandle and AdminEmail
					String KMUHandle = obj.get("KMUHandle").asString();
					String AdminEmail = obj.get("AdminEmail").asString();
					kmu = new KMU(KMUHandle,AdminEmail);
					JsonObject contents = obj.get("Contents").asObject();
					List<Block> list = bf.fromJsonObject(contents).getBlocks();
					// validate no confidential types found in export format, fail if we find one
					for(Block block: list){
						BlockType type = block.getBlockType();
						if(type == BlockType.X || type == BlockType.U) 
							throw new RuntimeException("Illegal type in Export Formatted file: "+type);
					}
					kmu.addBlocks(list);
					break;
				}
				case "Buttermilk Key Materials 1.0" : {
					throw new RuntimeException("Sorry, incompatible format for this reader.");
				}
				default: {
					throw new RuntimeException("Sorry, unknown format.");
				}
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		
		return kmu;
	}

}
