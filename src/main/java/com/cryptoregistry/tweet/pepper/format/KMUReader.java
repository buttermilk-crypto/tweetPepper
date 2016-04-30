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
 * Read the various blocks found in a JSON file and build a KMU or "Key Material Unit." A KMU is logically
 * similar in function to a key store but has more flexibility (e.g., can contain arbitrary data, contacts, etc).
 * 
 * @author Dave
 *
 */
public class KMUReader {
	
	private KMU kmu;
	private final Reader in;

	public KMUReader(Reader in) {
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
							data.put(dataKey, map.get(dataKey).asString());
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
							data.put(dataKey, map.get(dataKey).asString());
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

}
