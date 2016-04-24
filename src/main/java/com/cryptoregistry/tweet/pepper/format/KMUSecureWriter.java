package com.cryptoregistry.tweet.pepper.format;

import java.io.IOException;
import java.io.Writer;
import java.util.Iterator;

import com.cryptoregistry.json.Json;
import com.cryptoregistry.json.JsonObject;
import com.cryptoregistry.json.WriterConfig;
import com.cryptoregistry.tweet.pbe.PBEParams;
import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.KMU;


/**
 * Given blocks with unsecured keys, transform them into secured ones and emit the output. Filter out any other block
 * 
 * @author Dave
 *
 */
public class KMUSecureWriter {

	final KMU kmu;
	
	public KMUSecureWriter(KMU keyMaterialUnit, PBEParams params) {
		this.kmu = keyMaterialUnit;
	}
	
	public void writeTo(Writer writer){
		
		//Contents object
		JsonObject contents = new JsonObject();
		
		Iterator<String> iter = kmu.map.keySet().iterator();
		while(iter.hasNext()){
			String key = iter.next(); // distinguished name
			if(!key.endsWith("-U")) continue;
			Block map = kmu.map.get(key);
			JsonObject obj = new JsonObject();
			Iterator<String> biter = map.keySet().iterator();
			while(biter.hasNext()){
				String itemKey = biter.next();
				String itemValue = map.get(itemKey);
				obj.add(itemKey, itemValue);
			}
			contents.add(key, obj);
		}
		
		String output = Json.object()
		.add("Version", KMU.confidentialKeyVersion)
		.add("Contents", contents).toString(WriterConfig.PRETTY_PRINT);
		try {
			writer.write(output);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

}
