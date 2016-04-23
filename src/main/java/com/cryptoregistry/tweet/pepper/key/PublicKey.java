
package com.cryptoregistry.tweet.pepper.key;

import java.util.Arrays;

public class PublicKey extends Key {

	public PublicKey(byte[] bytes) {
		super(bytes);
	}
	
	PublicKey(byte[] bytes,boolean alive) {
		super(bytes,alive);
	}
	
	public boolean equals(Object obj){
		if (this == obj) return true;
		if (obj == null) return false;
		if (getClass() != obj.getClass()) return false;
		PublicKey k = (PublicKey) obj;
		if((this.alive != k.alive)) return false; 
		return Arrays.equals(this.getBytes(),k.getBytes());
	}

}
