package com.cryptoregistry.tweet.pepper;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * <p>A Block is a linked hash map with a unique identifier and a type:</p>
 * 
 * <ol>
 *  <li>C = Contact data</li>
 *  <li>D = arbitrary string keys and values, Data</li>
 *  <li>P = key, for Publication part only</li>
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
	
	public String name;

	public Block(BlockType type) {
		super();
		name = UUID.randomUUID().toString()+"-"+type.toString();
	}
	
	public Block(String uuid, BlockType type) {
		super();
		name = uuid+"-"+type.toString();
	}
	
	public Block(String dName) {
		super();
		name = dName;
	}
	
	public BlockType getBlockType() {
		final char val = name.charAt(name.length()-1);
		switch(val){
		case 'C': return BlockType.C; 
		case 'D': return BlockType.D;
		case 'P': return BlockType.P;
		case 'U': return BlockType.U;
		case 'X': return BlockType.X;
		case 'S': return BlockType.S;
		case 'T': return BlockType.T;
		default: throw new RuntimeException("Unknown category: "+val);
		}
	}
	
	public boolean isU(){
		return getBlockType()==BlockType.U;
	}
	
	public boolean isX(){
		return getBlockType()==BlockType.X;
	}
	
	public String toString() {
		return name;
	}
	
	public void loadToSignatureScope(Map<String,String> scopeMap){
		for(String key: keySet()) {
			String value = get(key);
			scopeMap.put(name+":"+key, value);
		}
	}

}