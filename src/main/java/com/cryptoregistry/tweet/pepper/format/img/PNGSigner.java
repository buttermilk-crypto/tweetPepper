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

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Base64;

import com.cryptoregistry.digest.sha3.SHA3Digest;
import com.cryptoregistry.tweet.pepper.Block;
import com.cryptoregistry.tweet.pepper.BlockType;
import com.cryptoregistry.tweet.pepper.KMU;
import com.cryptoregistry.tweet.pepper.format.KMUOutputAdapter;
import com.cryptoregistry.tweet.pepper.key.SigningKeyContents;


/**
 * <p>This class leverages the idea that PNG data format has lossless compression so the original image 
 * data should be amenable to a digital signature. It also leverages the chunk format. It reads 
 * a PNG-formatted file and creates a SHA3 digest over the IDAT chunk data, and writes an embedded 
 * JSON file into a chunk with the tag "tpSi". The data in this chunk is zlib compressed. </p>
 * 
 * <p>The signFile() method can be called repeatedly on an arbitrary number of files.</p>
 * 
 * <p>If an existing tpSi chunk is found, it will be replaced.</p>
 * 
 * <p>tpSi chunks always appear right before the IEND chunk (are always the second-to-last chunk).</p>
 * 
 * <p>This class does not require a graphics context.</p>
 
<p>The embedded JSON looks something like this:</p>

<pre>
{
  "Version": "Buttermilk Tweet Pepper 1.0",
  "KMUHandle": "Chinese_Knees",
  "AdminEmail": "dave@cryptoregistry.com",
  "Contents": {
    "2f18cpRAuoL5BKR0swGXaJ-P": {
      "KeyAlgorithm": "TweetNaCl",
      "KeyUsage": "Signing",
      "CreatedOn": "2016-05-22T09:13:17.932+10:00",
      "P": "ST04RKE8S8gVXwIz2MljBofEL_dDObHUD1ZgZWrTLUc="
    },
    "ca134XS7ktwn0AF5PwQtV-D": {
      "IDAT.digest.base64url": "GL0BwhpbzPWmziOxas34TsCQ6GSrEw_FRSR4F_-Lelk=",
      "IDAT.digest.alg": "SHA3"
    },
    "6RnMeP8ojCfbo4QFLtTbCl-S": {
      "CreatedOn": "2016-06-03T13:50:33.864+10:00",
      "DigestAlgorithm": "SHA3",
      "SignedWith": "2f18cpRAuoL5BKR0swGXaJ",
      "SignedBy": "Chinese_Knees",
      "s": [
        "jtVoQT1HJr3OrFkn-FV29PAta5e1a8-ztndv2pKZMMpnDJQf47iKqvmIGrTl1ipZYfT_BiiD",
        "BWP2tR02ErfuDTOj7-Ttp0DEx178ZCCOGGCe_6262Q0qomm6gmF36yjy"
      ],
      "DataRefs": [
        "6RnMeP8ojCfbo4QFLtTbCl-S:CreatedOn",
        ".SignedBy",
        ".SignedWith",
        "2f18cpRAuoL5BKR0swGXaJ-P:KeyAlgorithm",
        ".KeyUsage",
        ".CreatedOn",
        ".P",
        "ca134XS7ktwn0AF5PwQtV-D:IDAT.digest.base64url",
        ".IDAT.digest.alg"
      ]
    }
  }
}
</pre>
 
 
 * @author Dave
 *
 */
public class PNGSigner extends Constants {
	
	final SigningKeyContents sc;
	final String signer, adminEmail;
	public final SHA3Digest digest;
	
	public PNGSigner(String signer, String adminEmail, SigningKeyContents sc) {
		this.signer=signer;
		this.adminEmail=adminEmail;
		this.sc = sc;
		this.digest = new SHA3Digest();
	}
	
	/**
	 * Generic signing method for any PNG file. 
	 * 
	 * @param file
	 */
	public void signFile(File file){
		
		digest.reset();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream out = new DataOutputStream(baos);
		
		try(
		  InputStream in = new FileInputStream(file);
		){
			
			scan(in,out,null); 
			
			File bk = new File(file.getParentFile(),file.getName()+".bk");
			Files.copy(file.toPath(), bk.toPath()); // back up original
			Files.write(file.toPath(), baos.toByteArray());
		
		} catch (IOException e) {
			fail(e);
		}
	}
	
	/**
	 * Use this in tandem with PNGWrapperGenerator and PNGWrapperSpec
	 * 
	 * @param file
	 */
	public void signAndWrap(File file, KMU kmu){
		
		digest.reset();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream out = new DataOutputStream(baos);
		
		try(
		  InputStream in = new FileInputStream(file);
		){
			
			scan(in, out, kmu); 
			
			File bk = new File(file.getParentFile(),file.getName()+".bk");
			Files.copy(file.toPath(), bk.toPath(),StandardCopyOption.REPLACE_EXISTING); // back up original
			Files.write(file.toPath(), baos.toByteArray());
		
		} catch (IOException e) {
			fail(e);
		}
	}
	
	void scan(InputStream in, DataOutputStream out, KMU keystore) throws IOException {
		
		DataInputStream din = new DataInputStream(in);
		
		// consume and test header
		byte[]header = new byte[8];
		din.readFully(header, 0, 8);
		if(!Arrays.equals(Constants.HEADER, header)) fail("Header does not look like png format");
		out.write(Constants.HEADER);
		
		// loop through the chunks
		control: while(true){
			
			Chunk c = this.readChunk(din);
			
			// OK, we have the data for the chunk we've found, process the chunk
			
			switch(c.chunkType){
				case "IDAT": {
					
					// digest it
					digest.update(c.data, 0, (int)c.uInt);
					
					// just re-write the chunk to the output
					out.write(c.uIntBytes);
					out.write(c.type);
				    out.write(c.data);
					out.write(c.crcBytes);
					break;
				}
				case "tpSi": {
					// do not write an existing signature if found
					break;
				}
				case "tpKe": {
					// do not write an existing keystore if found
					break;
				}
				
				case "IEND": {
					
					// first write the keystore to out if there is one
					if(keystore != null){
						
						// get json from kmu
						StringWriter writer = new StringWriter();
						String keystoreJSON = new KMUOutputAdapter(keystore, false)
						  .writeTo(writer)
						  .toString();
						
						// compress as all good data gets compressed
						byte [] jsBytes = compress(keystoreJSON.getBytes(StandardCharsets.UTF_8));
						
						// digest data section so the signature has awareness of it
						digest.update(jsBytes, 0, jsBytes.length);
						
						// write as tpKe chunk
						this.writeChunk(KS_CHUNK, jsBytes, out);
						
					}
					
					// now create signature and write the tpSi chunk next
					
					// container for signature
					KMU kmu = new KMU();
					
					// do final digest
					byte[] hash = new byte[digest.getDigestSize()];
					digest.doFinal(hash, 0);

					// add our public key from the signer
					kmu.addBlock(sc.pubBlock());
					
					// build a data block with the digest
					Block block = new Block(BlockType.D);
					block.put("digest.0.base64url", Base64.getUrlEncoder().encodeToString(hash));
					kmu.addBlock(block);
					
					// create signature of the kmu and encode as JSON
				    String json = createSignature(sc,signer, kmu);
				    
				    // compress the json for use as data in a chunk
				    byte [] dataBytes = compress(json.getBytes(StandardCharsets.UTF_8));
					
					// write the new tpSi chunk as the second to last chunk
					
					this.writeChunk(SIG_CHUNK, dataBytes, out);
					
					// finally re-write IEND the chunk to the output
					out.write(c.uIntBytes);
					out.write(c.type);
					out.write(c.crcBytes);
					
					// now bail out of this loop
					break control;
				}
				default: {
					// chunks we don't look at but will keep
					// just re-write the chunk to the output
					out.write(c.uIntBytes);
					out.write(c.type);
					if(c.data != null) out.write(c.data);
					out.write(c.crcBytes);
				}
			}
		}
	}
	
}
