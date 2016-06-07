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
import com.cryptoregistry.json.JsonObject;
import com.cryptoregistry.json.WriterConfig;
import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.BlockType;
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
	final WriterConfig config;
	
	public KMUOutputAdapter(KMU keyMaterialUnit) {
		this(keyMaterialUnit,true);
	}
	
	public KMUOutputAdapter(KMU keyMaterialUnit, boolean pretty) {
		this.kmu = keyMaterialUnit;
		if(pretty)config = WriterConfig.PRETTY_PRINT;
		else config = WriterConfig.MINIMAL;
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
	
	public Writer writeTo(Writer writer){
		
		BlockFormatter bf = new BlockFormatter();
		Iterator<String> iter = kmu.map.keySet().iterator();
		while(iter.hasNext()){
			String key = iter.next(); // distinguished name
			Block block = kmu.map.get(key);
			BlockType type = block.getBlockType();
			if(type == BlockType.X || type == BlockType.U) 
				throw new RuntimeException("Illegal type in Export Formatted file: "+type);
			bf.addBlock(block);
		}
		
		JsonObject contents = bf.toJsonObject();
		
		String output = null;
		if(kmu.version.equals(KMU.transactionVersion)){
		   output = Json.object()
		   .add("Version", kmu.version)
		   .add("KMUHandle", kmu.kmuHandle)
		   .add("AdminEmail", kmu.adminEmail)
		   .add("Contents", contents).toString(config);
		}else{
			 output = Json.object()
			 .add("Version", kmu.version)
			.add("Contents", contents).toString(config);
		}
		
		try {
			writer.write(output);
			writer.flush();
			writer.close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		
		return writer;
	}
	
	/**
	 * Writes only the keys from a given KMU. This is to easily segregate out local contents
	 * 
	 * @param writer
	 */
	public Writer emitKeys(Writer writer){
		
		BlockFormatter bf = new BlockFormatter();
		Iterator<String> iter = kmu.map.keySet().iterator();
		while(iter.hasNext()){
			String key = iter.next(); // distinguished name
			Block block = kmu.map.get(key);
			BlockType type = block.getBlockType();
			// add only the keys
			if(!(type == BlockType.X || type == BlockType.U)) continue;
			bf.addBlock(block);
		}
		
		JsonObject contents = bf.toJsonObject();
		
		String output = Json.object()
		.add("Version", KMU.confidentialKeyVersion)
		.add("Contents", contents).toString(config);
		try {
			writer.write(output);
			writer.flush();
			writer.close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		
		return writer;
	}

}
