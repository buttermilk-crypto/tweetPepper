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
package com.cryptoregistry.tweet.pepper.format.img;

import java.util.LinkedHashMap;

/**
 * Details for the png file to be created
 * 
 * Defined values:
 * 
 * height
 * width
 * icon 
 * 
 * @author Dave
 *
 */
public class PNGWrapperSpec extends LinkedHashMap<String,String> {

	private static final long serialVersionUID = 1L;

	public PNGWrapperSpec() {
		super();
	}
	
	public int getInt(String key, int aDefault){
		if(!this.containsKey(key)) return aDefault;
		return Integer.parseInt(get(key));
	}
	
	public String get(String key, String aDefault){
		if(!this.containsKey(key)) return aDefault;
		return get(key);
	}

}
