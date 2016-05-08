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
import java.io.Writer;
import java.util.Iterator;

import com.cryptoregistry.json.Json;
import com.cryptoregistry.json.JsonObject;
import com.cryptoregistry.json.WriterConfig;
import com.cryptoregistry.tweet.pbe.PBEParams;
import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.KMU;


/**
 * Given blocks or a KMU with unsecured keys, transform them into secured ones and emit the output. 
 * Filter out any other block. This is used to write out confidential keys. This is a logical replacement for
 * PKCS#8 and possibly PKCS#12
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
