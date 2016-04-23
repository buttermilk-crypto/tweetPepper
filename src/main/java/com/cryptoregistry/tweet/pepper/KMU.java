package com.cryptoregistry.tweet.pepper;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * A KMU or "KeyMaterialUnit" is a set which can contain keys, signatures, and associated arbitrary data
 * 
 * @author Dave
 *
 */
public class KMU {

	public static final String version = "Buttermilk Tweet Pepper 1.0";
	public final String kmuHandle; // essentially a transaction handle, UUID that ends in "-T"
	public final String adminEmail; // immediate contact for failures, etc
	
	public final Map<String, Block> map; // keys are block distinguished names
	
	public KMU(String adminEmail) {
		super();
		this.kmuHandle = UUID.randomUUID().toString()+"-"+BlockType.T;
		this.adminEmail = adminEmail;
		this.map = new LinkedHashMap<String,Block>();
	}

	public KMU(String kmuHandle, String adminEmail) {
		super();
		this.kmuHandle = kmuHandle;
		this.adminEmail = adminEmail;
		this.map = new LinkedHashMap<String,Block>();
	}
	
	public void addBlock(Block block){
		map.put(block.toString(), block);
	}
}
