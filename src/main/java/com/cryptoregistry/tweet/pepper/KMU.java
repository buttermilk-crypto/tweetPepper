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

import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.cryptoregistry.tweet.pbe.PBE;
import com.cryptoregistry.tweet.pbe.PBEParams;
import com.cryptoregistry.tweet.pepper.key.BoxingKeyContents;
import com.cryptoregistry.tweet.pepper.key.BoxingKeyForPublication;
import com.cryptoregistry.tweet.pepper.key.SigningKeyContents;
import com.cryptoregistry.tweet.salt.pqc.NHKeyForPublication;
import com.cryptoregistry.tweet.url.BijectiveEncoder;

/**
 * A KMU or "KeyMaterialUnit" is a set which can contain keys, signatures, and associated arbitrary data.
 * 
 * When built for public use it has a unique transaction ID for use in transactions and an administrative 
 * contact email for issues
 * 
 * @author Dave
 *
 */
public class KMU {

	public static final String transactionVersion = "TweetPepper\u00AE Transaction Format 1.0";
	public static final String confidentialKeyVersion = "TweetPepper\u00AE Keystore Format 1.0";
	
	public final String version;
	public final String kmuHandle; // essentially a transaction handle, UUID that ends in "-T"
	public final String adminEmail; // immediate contact point for questions, failures, etc
	
	public final Map<String, Block> map; // keys are distinguished-names to the blocks
	public Map<String,String> aliases;
	
	public KMU() {
		super();
		this.version = confidentialKeyVersion;
		this.kmuHandle = null;
		this.adminEmail = null;
		this.map = new LinkedHashMap<String,Block>();
	}
	
	public KMU(Block...blocks){
		this();
		for(Block b: blocks){
			this.map.put(b.name,b);
		}
	}
	
	public KMU(String adminEmail) {
		super();
		this.version = transactionVersion;
		BijectiveEncoder enc= new BijectiveEncoder();
		this.kmuHandle = enc.encode(UUID.randomUUID())+"-"+BlockType.T;
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
	
	public KMU addBlocks(List<Block> blocks){
		for(Block block: blocks) map.put(block.toString(), block);
		return this;
	}
	
	// TODO
	public void addAlias(String alias, String name){
		if(aliases == null){
			
		}
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
	
	public BoxingKeyForPublication getBoxingPubKey(){
		for(String s: map.keySet()){
			Block b = map.get(s);
			if(b.name.endsWith("-P")){
				if(b.containsKey("KeyUsage")&&b.get("KeyUsage").equals("Boxing")) {
					// found a signing key
					return new BoxingKeyForPublication(b);
				}
			}
		}
		
		return null;
	}
	
	public NHKeyForPublication getNewHopePubKey(){
		for(String s: map.keySet()){
			Block b = map.get(s);
			if(b.name.endsWith("-P")){
				if(b.containsKey("KeyUsage")&&b.get("KeyUsage").equals("Agreement")) {
					// found an agreement key
					return new NHKeyForPublication(b);
				}
			}
		}
		
		return null;
	}
	
	/**
	 * merge some other KMU contents into this one (return this). Notices if a key is
	 * duplicate and does not take it on board
	 * 
	 * @param kmu
	 * @return
	 */
	public KMU mergeBlocks(KMU...kmus){
		for(KMU item: kmus){
			Iterator<String> iter = item.map.keySet().iterator();
			while(iter.hasNext()){
				String key = iter.next();
				if(this.map.containsKey(key))continue;
				else{
					this.map.put(key, item.map.get(key));
				}
			}
		}
		return this;
	}
	
	/**
	 * Return the first block of this type
	 * 
	 * @param type
	 * @return
	 */
	public Block findBlock(BlockType type){
		for(String s: map.keySet()){
			Block b = map.get(s);
			if(type.equals(b.getBlockType())) return b;
		}
		return null;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((adminEmail == null) ? 0 : adminEmail.hashCode());
		result = prime * result + ((aliases == null) ? 0 : aliases.hashCode());
		result = prime * result
				+ ((kmuHandle == null) ? 0 : kmuHandle.hashCode());
		result = prime * result + ((map == null) ? 0 : map.hashCode());
		result = prime * result + ((version == null) ? 0 : version.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		KMU other = (KMU) obj;
		if (adminEmail == null) {
			if (other.adminEmail != null)
				return false;
		} else if (!adminEmail.equals(other.adminEmail))
			return false;
		if (aliases == null) {
			if (other.aliases != null)
				return false;
		} else if (!aliases.equals(other.aliases))
			return false;
		if (kmuHandle == null) {
			if (other.kmuHandle != null)
				return false;
		} else if (!kmuHandle.equals(other.kmuHandle))
			return false;
		if (map == null) {
			if (other.map != null)
				return false;
		} else if (!map.equals(other.map))
			return false;
		if (version == null) {
			if (other.version != null)
				return false;
		} else if (!version.equals(other.version))
			return false;
		return true;
	}
	
	
	
}
