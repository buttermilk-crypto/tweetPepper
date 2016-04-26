package com.cryptoregistry.tweet.pepper.format;

import java.io.IOException;
import java.io.Writer;
import java.util.Iterator;

import com.cryptoregistry.json.Json;
import com.cryptoregistry.json.JsonObject;
import com.cryptoregistry.json.WriterConfig;
import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.KMU;


/**
 * Serialize to JSON. We're using internal classes for this (taken from https://github.com/ralfstx/minimal-json)
 * to avoid external dependencies
 * 
 * @author Dave
 *
 */
public class KMUWriter {

	final KMU kmu;
	
	public KMUWriter(KMU keyMaterialUnit) {
		this.kmu = keyMaterialUnit;
	}
	
	public void writeTo(Writer writer){
		
		//Contents object
		JsonObject contents = new JsonObject();
		
		Iterator<String> iter = kmu.map.keySet().iterator();
		while(iter.hasNext()){
			String key = iter.next(); // distinguished name
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
		
		String output = null;
		if(kmu.version.equals(KMU.transactionVersion)){
		   output = Json.object()
		   .add("Version", kmu.version)
		   .add("KMUHandle", kmu.kmuHandle)
		   .add("AdminEmail", kmu.adminEmail)
		   .add("Contents", contents).toString(WriterConfig.PRETTY_PRINT);
		}else{
			 output = Json.object()
			 .add("Version", kmu.version)
			.add("Contents", contents).toString(WriterConfig.PRETTY_PRINT);
		}
		
		try {
			writer.write(output);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	public void emitKeys(Writer writer){
		
		//Contents object
		JsonObject contents = new JsonObject();
		
		Iterator<String> iter = kmu.map.keySet().iterator();
		while(iter.hasNext()){
			String key = iter.next(); // distinguished name
			if(key.endsWith("-U")||key.endsWith("-X")){ 
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
