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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

import com.cryptoregistry.json.Json;
import com.cryptoregistry.json.JsonArray;
import com.cryptoregistry.json.JsonObject;
import com.cryptoregistry.json.JsonValue;
import com.cryptoregistry.json.WriterConfig;
import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.KMU;


/**
 * Serialize KMU contents to JSON. We're using package-internal classes for this 
 * (taken from https://github.com/ralfstx/minimal-json) to avoid external dependencies 
 * such as Jackson. This is partly for license reasons - this is a GNU licensed project -
 * but also just to make the package as complete in itself as possible.
 * 
 * @author Dave
 *
 */
public class KMUOutputAdapter {

	final KMU kmu;
	
	public KMUOutputAdapter(KMU keyMaterialUnit) {
		this.kmu = keyMaterialUnit;
	}
	
	public void writeTo(File file){
		try {
			FileOutputStream out = new FileOutputStream(file);
			OutputStreamWriter writer = new OutputStreamWriter(out, StandardCharsets.UTF_8);
			this.writeTo(writer);
		} catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		}
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
				if(itemValue.length() >= JsonValue.TRANSFORM_LINE_LENGTH){
					obj.add(itemKey, split(itemValue, 72));
				}else{
					obj.add(itemKey, itemValue);
				}
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
			writer.flush();
			writer.close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	private JsonArray split(String input, int length){
		JsonArray array = new JsonArray();
		if(input.length() <= length) {
			array.add(input);
			return array;
		}
		int lineCount = (input.length() / length);
		int charCount = 0;
		for(int i = 0;i<lineCount;i++){
			int start = charCount;
			int end = start+length;
			String substring = input.substring(start, end);
			array.add(substring);
			charCount+=length;
		}
		String last = input.substring(charCount, input.length());
		array.add(last);
		return array;
	}
	
	/**
	 * Writes only the keys from a given KMU. This is to easily segregate out local contents
	 * 
	 * @param writer
	 */
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
					if(itemValue.length() >= JsonValue.TRANSFORM_LINE_LENGTH){
						obj.add(itemKey, split(itemValue, 72));
					}else{
						obj.add(itemKey, itemValue);
					}
				}
				contents.add(key, obj);
			}
		}
		
		String output = Json.object()
		.add("Version", KMU.confidentialKeyVersion)
		.add("Contents", contents).toString(WriterConfig.PRETTY_PRINT);
		try {
			writer.write(output);
			writer.flush();
			writer.close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

}
