package com.cryptoregistry.tweet.pepper.format;

import java.io.Writer;

import com.cryptoregistry.tweet.pepper.KMU;


/**
 * Serialize to JSON. We're using our own internal classes for this (taken from https://github.com/ralfstx/minimal-json)
 * to avoid external dependencies
 * 
 * @author Dave
 *
 */
public class KMUWriter {

	final KMU keyMaterialUnit;
	
	public KMUWriter(KMU keyMaterialUnit) {
		this.keyMaterialUnit = keyMaterialUnit;
	}
	
	public void writeTo(Writer writer){
	
	}

}
