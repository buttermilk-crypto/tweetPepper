package com.cryptoregistry.tweet.pepper;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A KMU or "KeyMaterialUnit" is a set which can contain keys, signatures, and associated arbitrary data
 * 
 * @author Dave
 *
 */
public class KMU {

	public final String kmuHandle; // essentially a transaction handle, UUID that ends in "-T"
	public final String adminEmail; // immediate contact for failures, etc
	
	public final Map<String, Block<String,String>> map; // keys are block distinguished names

	public KMU(String kmuHandle, String adminEmail) {
		super();
		this.kmuHandle = kmuHandle;
		this.adminEmail = adminEmail;
		this.map = new LinkedHashMap<String,Block<String,String>>();
	}
	
	public void addBlock(Block<String,String> block){
		map.put(block.toString(), block);
	}

}
