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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.cryptoregistry.json.Json;
import com.cryptoregistry.json.JsonArray;
import com.cryptoregistry.json.JsonObject;
import com.cryptoregistry.json.JsonValue;
import com.cryptoregistry.json.WriterConfig;
import com.cryptoregistry.tweet.pepper.Block;

/**
 * Two-way transform blocks-to-json or vice-versa. This is parsing and formatting the "Contents" part of a KMU
 * 
 * @author Dave
 *
 */
public final class BlockFormatter {

	private List<Block> blocks;
	private String json;
	private boolean pretty;
	
	public BlockFormatter() {
		blocks = new ArrayList<Block>();
		pretty = true;
	}
	
	public BlockFormatter(WriterConfig config) {
		blocks = new ArrayList<Block>();
		if(config == WriterConfig.PRETTY_PRINT) pretty=true;
		else pretty=false;
	}

	public BlockFormatter(Block block) {
		this();
		blocks.add(block);
	}

	public BlockFormatter(Block[] input) {
		this();
		for (Block b : input) {
			this.blocks.add(b);
		}
	}

	public BlockFormatter(String json) {
		this();
		this.json = json;
	}

	public BlockFormatter setPretty(boolean makePretty) {
		pretty = makePretty;
		return this;
	}

	public BlockFormatter addBlock(Block block) {
		blocks.add(block);
		return this;
	}

	public Block getBlock(int index) {
		return blocks.get(index);
	}

	public JsonObject toJsonObject() {
		if (blocks.size() == 0)
			throw new RuntimeException("use the Block constructor first");
		// root object
		JsonObject contents = new JsonObject();
		for (Block block : blocks) {
			JsonObject obj = new JsonObject();
			Iterator<String> biter = block.keySet().iterator();
			while (biter.hasNext()) {
				String itemKey = biter.next();
				String itemValue = block.get(itemKey);
				
				if(pretty){
					// special case
					if (itemKey.equals("DataRefs")) {
						obj.add(itemKey, splitByComma(itemValue));
					} else {
						if (itemValue.length() >= JsonValue.TRANSFORM_LINE_LENGTH) {
							obj.add(itemKey, split(itemValue, 72));
						} else {
							obj.add(itemKey, itemValue);
						}
					}
				}else{
					obj.add(itemKey, itemValue);
				}
				
			}
			contents.add(block.name, obj);
		}

		return contents;
	}

	public BlockFormatter buildJSON() {

		JsonObject contents = toJsonObject();
		if (pretty)
			json = contents.toString(WriterConfig.PRETTY_PRINT);
		else
			json = contents.toString(WriterConfig.MINIMAL);
		return this;
	}

	public BlockFormatter buildBlocks() {
		if (json == null)
			throw new RuntimeException("use the String constructor first");
		blocks.clear();
		JsonValue root = Json.parse(json);
		JsonObject obj = root.asObject();

		List<String> names = obj.names(); // list of dnames

		for (String dname : names) {

			Block block = new Block(dname);
			JsonValue map = obj.get(dname);
			JsonObject blk = map.asObject();
			for (String dataKey : blk.names()) {
				JsonValue v = blk.get(dataKey);
				if (v.isArray()) { // auto-marshalling string vs. array
					JsonArray array = blk.get(dataKey).asArray();
					
					if (dataKey.equals("DataRefs")) {
						block.put(dataKey, combineCommaDelimited(array));
					} else {
						block.put(dataKey, combine(array));
					}
					
				} else if (v.isString()) {
					block.put(dataKey, blk.get(dataKey).asString());
				}
			}

			blocks.add(block);
		}
		
		return this;
	}

	public BlockFormatter fromJsonObject(JsonObject obj) {

		blocks.clear();
		List<String> names = obj.names(); // list of dnames

		for (String dname : names) {

			Block block = new Block(dname);
			JsonValue map = obj.get(dname);
			JsonObject blk = map.asObject();
			for (String dataKey : blk.names()) {
				JsonValue v = blk.get(dataKey);
				if (v.isArray()) { // auto-marshalling string vs. array
					JsonArray array = blk.get(dataKey).asArray();
					if (dataKey.equals("DataRefs")) {
						block.put(dataKey, combineCommaDelimited(array));
					} else {
						block.put(dataKey, combine(array));
					}
				} else if (v.isString()) {
					block.put(dataKey, blk.get(dataKey).asString());
				}
			}

			blocks.add(block);
		}
		
		return this;

	}

	private String combine(JsonArray array) {
		Iterator<JsonValue> iter = array.iterator();
		StringBuilder b = new StringBuilder();
		while (iter.hasNext()) {
			b.append(iter.next().asString());
		}
		return b.toString();
	}

	private String combineCommaDelimited(JsonArray array) {
		Iterator<JsonValue> iter = array.iterator();
		StringBuilder b = new StringBuilder();
		while (iter.hasNext()) {
			b.append(iter.next().asString());
			b.append(", ");
		}
		b.delete(b.length() - 2, b.length());
		return b.toString();
	}

	private JsonArray split(String input, int length) {
		JsonArray array = new JsonArray();
		if (input.length() <= length) {
			array.add(input);
			return array;
		}
		int lineCount = (input.length() / length);
		int charCount = 0;

		for (int i = 0; i < lineCount; i++) {
			int start = charCount;
			int end = start + length;
			String substring = input.substring(start, end);
			array.add(substring);
			charCount += length;
		}
		String last = input.substring(charCount, input.length());
		if (last.length() < 10) {
			// if last is small it looks better to put at end of previous
			// substring
			array.appendToLast(last);
		} else
			array.add(last);
		return array;
	}

	/**
	 * Split by comma, this is used for DataRefs
	 * 
	 * @param input
	 * @return
	 */
	private JsonArray splitByComma(String input) {
		JsonArray array = new JsonArray();
		if (!input.contains(",")) {
			array.add(input);
			return array;
		}
		String[] list = input.split("\\,");

		for (String part : list) {
			array.add(part.trim());
		}

		return array;
	}

	public List<Block> getBlocks() {
		return blocks;
	}

	public String getJson() {
		return json;
	}
}
