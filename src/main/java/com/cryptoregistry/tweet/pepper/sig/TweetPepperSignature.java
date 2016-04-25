package com.cryptoregistry.tweet.pepper.sig;

import java.util.List;

import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.BlockType;
import com.cryptoregistry.util.TimeUtil;

public class TweetPepperSignature {

	public final TweetSignatureMetadata metadata;
	public final String signature; // base64url encoded
	public final List<String> tokens;
	
	public TweetPepperSignature(TweetSignatureMetadata metadata, String signature, List<String> tokens) {
		super();
		this.metadata = metadata;
		this.signature = signature;
		this.tokens = tokens;
	}
	
	public Block toBlock() {
		Block b = new Block(metadata.handle, BlockType.S);
		b.put("CreatedOn",TimeUtil.format(this.metadata.createdOn));
        b.put("DigestAlgorithm", this.metadata.digestAlg);
        b.put("SignedWith", this.metadata.signedWith);
        b.put("SignedBy", this.metadata.signedBy);
        b.put("s", signature);
        b.put("DataRefs", listToString());
		return b;
	}
	
	private String listToString() {
		StringBuffer buf = new StringBuffer();
		for(String token: tokens){
			buf.append(token);
			buf.append(", ");
		}
		buf.delete(buf.length()-2, buf.length());
		return buf.toString();
	}
	
}
