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

package com.cryptoregistry.tweet.pepper;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import com.cryptoregistry.tweet.url.BijectiveEncoder;

/**
 * <p>A Block is a linked hash map with a unique identifier and a type:</p>
 * 
 * <ol>
 *  <li>C = Contact data</li>
 *  <li>D = arbitrary string keys and values, Data</li>
 *  <li>E = encrypted data</li>
 *  <li>P = key, for-publication part only</li>
 *  <li>U = key contents, unsecured</li>
 *  <li>X = key contents, secured/encrypted</li>
 *  <li>S = Signature block</li>
 *  <li>T = Transaction block</li>
 * </ol>
 * 
 * 
 * @author Dave
 *
 */
public class Block extends LinkedHashMap<String,String> {

	private static final long serialVersionUID = 1L;
	
	public String name; // canonical name - should be globally unique such as a UUID

	public Block(BlockType type) {
		super();
		BijectiveEncoder bj = new BijectiveEncoder();
		name = bj.encode(UUID.randomUUID())+"-"+type.toString();
	}
	
	public Block(String base, BlockType type) {
		super();
		name = base+"-"+type.toString();
	}
	
	/**
	 * Used with the full Base-BlockType value
	 *  
	 * @param dName
	 */
	public Block(String dName) {
		super();
		name = dName;
	}
	
	public BlockType getBlockType() {
		final char val = name.charAt(name.length()-1);
		switch(val){
		case 'C': return BlockType.C; 
		case 'D': return BlockType.D;
		case 'E': return BlockType.E;
		case 'P': return BlockType.P;
		case 'U': return BlockType.U;
		case 'X': return BlockType.X;
		case 'S': return BlockType.S;
		case 'T': return BlockType.T;
		default: throw new RuntimeException("Unknown category: "+val);
		}
	}
	
	public boolean isP(){
		return getBlockType()==BlockType.P;
	}
	
	public boolean isU(){
		return getBlockType()==BlockType.U;
	}
	
	public boolean isX(){
		return getBlockType()==BlockType.X;
	}
	
	public boolean isSigner(){
		return this.containsKey("KeyUsage") && this.get("KeyUsage").equals("Signing");
	}
	
	public boolean isBoxing(){
		return this.containsKey("KeyUsage") && this.get("KeyUsage").equals("Boxing");
	}
	
	public boolean isSecretBox(){
		return this.containsKey("KeyUsage") && this.get("KeyUsage").equals("SecretBox");
	}
	
	public String toString() {
		return name;
	}
	
	public String baseName() {
		return name.substring(0, name.length()-2);
	}
	
	/**
	 * Return a traditional UUID
	 * 
	 * @return
	 */
	public UUID baseToUUID() {
		BijectiveEncoder bj = new BijectiveEncoder();
		return bj.decode(baseName());
	}
	
	/**
	 * loads our contents into a map which is used for signature validation
	 * 
	 * @param scopeMap
	 */
	public void loadToSignatureScope(Map<String,String> scopeMap){
		for(String key: keySet()) {
			String value = get(key);
			scopeMap.put(name+":"+key, value);
		}
	}
	
	public byte [] getBytesFromBase64urlString(String key){
		if(!this.containsKey(key))throw new RuntimeException("key not present: "+key);
		return Base64.getUrlDecoder().decode(get(key));
	}
	
}
