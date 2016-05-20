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
import java.util.Iterator;
import java.util.List;

import com.cryptoregistry.json.Json;
import com.cryptoregistry.json.JsonArray;
import com.cryptoregistry.json.JsonObject;
import com.cryptoregistry.json.JsonValue;
import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.BlockType;
import com.cryptoregistry.tweet.pepper.KMU;

/**
 * Read a JSON file and build a KMU or "Key Material Unit" object. A KMU is logically similar in function 
 * to a key store but has more flexibility (e.g., can contain arbitrary data, contacts, etc).
 * 
 * @author Dave
 *
 */
public class KMUInputAdapter {
	
	private KMU kmu;
	private final Reader in;

	public KMUInputAdapter(Reader in) {
		this.in = in;
	}
	
	public KMU read(){
	
		try {
			JsonValue root = Json.parse(in);
			JsonObject obj = root.asObject();
			String version = obj.get("Version").asString(); //all Tweet formats have a version
			switch(version){
				case "Buttermilk Tweet Pepper Keys 1.0": {
					kmu = new KMU();
					// we expect an arbitrary number of keys (-X) or -U as the Contents but  other 
					// types are ok if required
					JsonObject contents = obj.get("Contents").asObject();
					List<String> names = contents.names();
					for(String name: names){
						JsonValue keyValue = contents.get(name);
						JsonObject map = keyValue.asObject();
						Block data = new Block(name);
						List<String> dataKeys = map.names();
						for(String dataKey: dataKeys){
							JsonValue v = map.get(dataKey);
							if(v.isArray()){ // auto-marshalling string vs. array
								JsonArray array = map.get(dataKey).asArray();
								if(dataKey.equals("DataRefs")){
									data.put(dataKey, combineWithCommas(array));
								}else{
									data.put(dataKey, combine(array));
								}
							}else if(v.isString()){
								data.put(dataKey, map.get(dataKey).asString());
							}
						}
						kmu.addBlock(data);
					}
					
					break;
				}
				case "Buttermilk Tweet Pepper 1.0" : {
					// would not contain -X or -U, as these confidential bits should not be exported
					// but would contain KMUHandle and AdminEmail
					String KMUHandle = obj.get("KMUHandle").asString();
					String AdminEmail = obj.get("AdminEmail").asString();
					kmu = new KMU(KMUHandle,AdminEmail);
					JsonObject contents = obj.get("Contents").asObject();
					List<String> names = contents.names();
					for(String name: names){
						BlockType type = BlockType.fromFlag(name.substring(name.length()-2, name.length()));
						// prevent confidential types here
						if(type == BlockType.X || type == BlockType.U) 
							throw new RuntimeException("Illegal type in Export Format file: "+type);
						JsonValue keyValue = contents.get(name);
						JsonObject map = keyValue.asObject();
						Block data = new Block(name);
						List<String> dataKeys = map.names();
						for(String dataKey: dataKeys){
							JsonValue v = map.get(dataKey);
							if(v.isArray()){ // auto-marshalling string vs. array
							JsonArray array = map.get(dataKey).asArray();
								data.put(dataKey, combine(array));
							}else if(v.isString()){
								data.put(dataKey, map.get(dataKey).asString());
							}
						}
						kmu.addBlock(data);
					}
					
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
	
	private String combine(JsonArray array){
		Iterator<JsonValue> iter = array.iterator();
		StringBuilder b = new StringBuilder();
		while(iter.hasNext()){
			b.append(iter.next().asString());
		}
		return b.toString();
	}
	
	private String combineWithCommas(JsonArray array){
		Iterator<JsonValue> iter = array.iterator();
		StringBuilder b = new StringBuilder();
		while(iter.hasNext()){
			b.append(iter.next().asString());
			b.append(",");
		}
		b.deleteCharAt(b.length()-1);
		return b.toString();
	}

}
