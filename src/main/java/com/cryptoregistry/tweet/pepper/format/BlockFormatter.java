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

import java.util.Iterator;
import java.util.List;

import com.cryptoregistry.json.Json;
import com.cryptoregistry.json.JsonArray;
import com.cryptoregistry.json.JsonObject;
import com.cryptoregistry.json.JsonValue;
import com.cryptoregistry.json.WriterConfig;
import com.cryptoregistry.tweet.pepper.Block;

/**
 *<pre>
 
  Format an individual block into json or json to a block. 
  
  		Block block = new Block(BlockType.D);
		block.put("Small", "a small value");
		block.put("Larger", "111...6666");
		
		BlockFormatter bf = new BlockFormatter(block);
		bf.setPretty(true);
		String s = bf.toJSON();
		System.err.println(s);
		Block output = bf.fromJSON();
		Assert.assertTrue(output.equals(block));
  
  Has output data block:
  
	 {
	  "2AhnH4zdjDfRPYVimZr8eL-D": {
	    "Small": "a small value",
	    "Larger": [
	      "111111111111111111111111111111111111111222222222222222222222222222222222",
	      "222222222222222333333333333333333333333333333333344444444444444444444444",
	      "444444444444455555555555555555555555555555555555566666666666666666666666",
	      "6666666666666666666"
	    ]
	  }
	 }
 
 Larger will be available as a String, just like Smaller. This is due to auto-marshalling of long strings into arrays
 
 * </pre>
 * @author Dave
 *
 */
public class BlockFormatter {

	private Block block;
	private String json;
	private boolean pretty;
	
	public BlockFormatter(Block block) {
		this.block = block;
	}
	
	public BlockFormatter(Block block, boolean pretty) {
		this.block = block;
		this.pretty = pretty;
	}
	
	public BlockFormatter(String json) {
		this.json = json;
	}
	
	public void setPretty(boolean makePretty){
		pretty= makePretty;
	}
	
    public String toJSON()  {
    	if(block == null) throw new RuntimeException("use the Block constructor first");
		JsonObject contents = new JsonObject();
		
		JsonObject obj = new JsonObject();
		Iterator<String> biter = block.keySet().iterator();
		while(biter.hasNext()){
			String itemKey = biter.next();
			String itemValue = block.get(itemKey);
			if(itemValue.length() >= JsonValue.TRANSFORM_LINE_LENGTH){
				obj.add(itemKey, split(itemValue, 72));
			}else{
				obj.add(itemKey, itemValue);
			}
		}
		contents.add(block.name, obj);
		if(pretty) json = contents.toString(WriterConfig.PRETTY_PRINT);
		else json = contents.toString(WriterConfig.MINIMAL);
		return json;
	}
	
	public Block fromJSON(){
		if(json == null) throw new RuntimeException("use the String constructor first");
		JsonValue root = Json.parse(json);
		JsonObject obj = root.asObject();
		List<String> names = obj.names();
		//should be only one
		if(names.size() != 1) throw new RuntimeException("Should be only one block here, found "+names.size());
		String dname = names.get(0);
		block = new Block(dname);
		JsonValue map = obj.get(dname);
		JsonObject blk = map.asObject();
		for(String dataKey: blk.names()){
				JsonValue v = blk.get(dataKey);
				if(v.isArray()){ // auto-marshalling string vs. array
				JsonArray array = blk.get(dataKey).asArray();
					block.put(dataKey, combine(array));
				}else if(v.isString()){
					block.put(dataKey, blk.get(dataKey).asString());
				}
		}
		return block;
	}
	
	private String combine(JsonArray array){
		Iterator<JsonValue> iter = array.iterator();
		StringBuilder b = new StringBuilder();
		while(iter.hasNext()){
			b.append(iter.next().asString());
		}
		return b.toString();
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

}
