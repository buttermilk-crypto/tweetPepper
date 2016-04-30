package com.cryptoregistry.tweet.pepper;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.cryptoregistry.tweet.pbe.PBE;
import com.cryptoregistry.tweet.pbe.PBEParams;
import com.cryptoregistry.tweet.pepper.key.BoxingKeyContents;
import com.cryptoregistry.tweet.pepper.key.SigningKeyContents;

/**
 * A KMU or "KeyMaterialUnit" is a set which can contain keys, signatures, and associated arbitrary data.
 * It has a unique transaction ID for use in transactions and an administrative contact email
 * 
 * @author Dave
 *
 */
public class KMU {

	public static final String transactionVersion = "Buttermilk Tweet Pepper 1.0";
	public static final String confidentialKeyVersion = "Buttermilk Tweet Pepper Keys 1.0";
	
	public final String version;
	public final String kmuHandle; // essentially a transaction handle, UUID that ends in "-T"
	public final String adminEmail; // immediate contact for failures, etc
	
	public final Map<String, Block> map; // keys are distinguished-names to the blocks
	
	public KMU() {
		super();
		this.version = confidentialKeyVersion;
		this.kmuHandle = null;
		this.adminEmail = null;
		this.map = new LinkedHashMap<String,Block>();
	}
	
	public KMU(String adminEmail) {
		super();
		this.version = transactionVersion;
		this.kmuHandle = UUID.randomUUID().toString()+"-"+BlockType.T;
		this.adminEmail = adminEmail;
		this.map = new LinkedHashMap<String,Block>();
	}

	public KMU(String kmuHandle, String adminEmail) {
		super();
		this.version = transactionVersion;
		this.kmuHandle = kmuHandle;
		this.adminEmail = adminEmail;
		this.map = new LinkedHashMap<String,Block>();
	}
	
	public KMU addBlock(Block block){
		map.put(block.toString(), block);
		return this;
	}
	
	/**
	 * <p>Any blocks of type -U will be altered:</p>
	 * 
	 * <ol>
	 * 		<li>S will be encrypted and changed to X</li>
	 * 		<li>the distinguished name will be changed to -X</li>
	 * </ol>
	 * 
	 * <p>If the password value is forgotten there is no way to re-set it, and it cannot be set to null</p>
	 * 
	 * <p>this method takes some time and CPU, which is intentional. SCrypt is a strong KDF.</p>
	 * 
	 * @param password
	 */
	public void protectKeyBlocks(char [] password) {
		List<Block> list = new ArrayList<Block>();
		for(String s: map.keySet()){
			Block b = map.get(s);
			if(b.name.endsWith("-U")){
				String base64UnsecureKey = b.get("S");
				PBEParams params = new TweetPepper().createPBEParams();
				PBE pbe = new PBE(params);
				String enc = pbe.protect(password, Base64.getUrlDecoder().decode(base64UnsecureKey));
				b.remove("S");
				b.put("X", enc);
				list.add(b);
			}
		}
		for(Block b: list){
			map.remove(b.name);
			b.name = b.name.substring(0,b.name.length()-2)+"-X";
			map.put(b.name, b);
		}
	}
	
	/**
	 * Open (unencrypt) blocks of type -X if found in the KMU. Currently this expects all protected keys to
	 * have the same password.
	 * 
	 * @param password
	 */
	public void openKeyBlocks(char [] password) {
		for(String s: map.keySet()){
			Block b = map.get(s);
			if(b.name.endsWith("-X")){
				String base64SecureKey = b.get("X");
				PBE pbe = new PBE();
				byte [] confidentialKey = pbe.unprotect(password, base64SecureKey);
				b.remove("X");
				b.put("S", Base64.getUrlEncoder().encodeToString(confidentialKey));
				b.name = b.name.substring(0,b.name.length()-2)+"-U";
			}
		}
	}
	
	/**
	 * Given a block name, add (or update an existing) key and value
	 * 
	 * @param blockname
	 * @param key
	 * @param value
	 */
	public void updateBlock(String blockname, String key, String value){
		for(String dname: map.keySet()){
			if(blockname.equals(dname)){
				Block item = map.get(dname);
				item.put(key, value);
				return;
			}
		}
	}
	
	public void removeBlockItem(String blockname, String key){
		for(String dname: map.keySet()){
			if(blockname.equals(dname)){
				Block item = map.get(dname);
				item.remove(key);
				return;
			}
		}
	}
	
	/**
	 * Return the first appropriate block found as a rehydrated key or null if none found
	 * 
	 * @return the reydrated key if found
	 */
	public SigningKeyContents getSigningKey(){
		for(String s: map.keySet()){
			Block b = map.get(s);
			if(b.name.endsWith("-U")){
				if(b.containsKey("KeyUsage")&&b.get("KeyUsage").equals("Signing")) {
					// found a signing key
					return new SigningKeyContents(b);
				}
			}
		}
		
		return null;
	}
	
	/**
	 * Return the first appropriate block found as a rehydrated key or null if none found
	 * 
	 * @return the reydrated key if found
	 */
	public BoxingKeyContents getBoxingKey(){
		for(String s: map.keySet()){
			Block b = map.get(s);
			if(b.name.endsWith("-U")){
				if(b.containsKey("KeyUsage")&&b.get("KeyUsage").equals("Boxing")) {
					// found a signing key
					return new BoxingKeyContents(b);
				}
			}
		}
		
		return null;
	}
	
}
