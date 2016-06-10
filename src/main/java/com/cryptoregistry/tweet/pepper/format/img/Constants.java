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

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import com.cryptoregistry.tweet.pepper.KMU;
import com.cryptoregistry.tweet.pepper.format.KMUOutputAdapter;
import com.cryptoregistry.tweet.pepper.key.SigningKeyContents;
import com.cryptoregistry.tweet.pepper.sig.TweetPepperSHA3Signer;
import com.cryptoregistry.tweet.pepper.sig.TweetPepperSignature;

/**
 * Base class for PNG format and generally working with chunks. Does not require a graphics context.
 * 
 * @author Dave
 *
 */
public class Constants {

	// constant bytes for the PNG header
	static final byte[] HEADER = { (byte) 137, (byte) 80, (byte) 78, (byte) 71,
			(byte) 13, (byte) 10, (byte) 26, (byte) 10 };

	// "tpSi = tweet pepper Signed image"
	static final byte[] SIG_CHUNK = { (byte) 't', (byte) 'p', (byte) 'S', (byte) 'i' };

	// "tpKe = tweet pepper Key store"
	static final byte[] KS_CHUNK = { (byte) 't', (byte) 'p', (byte) 'K', (byte) 'e' };

	protected void fail(String msg) {
		throw new RuntimeException("error: " + msg);
	}

	protected void fail(Exception msg) {
		throw new RuntimeException(msg);
	}
	
	protected long uint(byte[]b){
		 return(((b[0]&0xff)<<24) +
	               ((b[1]&0xff)<<16) +
	               ((b[2]&0xff)<<8) +
	               ((b[3]&0xff)));
	}

	protected String chunkType(byte[] bytes) {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < 4; i++)
			buf.append((char) bytes[i]);
		return buf.toString();
	}

	protected byte[] compress(byte[] inBytes) {
		byte[] output = new byte[inBytes.length]; // baseline
		Deflater compresser = new Deflater();
		compresser.setInput(inBytes);
		compresser.finish();
		int compressedDataLength = compresser.deflate(output);
		compresser.end();
		byte[] out = new byte[compressedDataLength];
		System.arraycopy(output, 0, out, 0, compressedDataLength);
		return out;
	}

	protected byte[] decompress(byte[] inBytes) {
		Inflater decompresser = new Inflater();
		decompresser.setInput(inBytes, 0, inBytes.length);
		byte[] result = new byte[inBytes.length * 5];
		int resultLength;
		try {
			resultLength = decompresser.inflate(result);
		} catch (DataFormatException e) {
			throw new RuntimeException(e);
		}
		decompresser.end();

		byte[] out = new byte[resultLength];
		System.arraycopy(result, 0, out, 0, resultLength);
		return out;

	}

	protected void writeCRC(byte[] chunkTypeBytes, byte[] data, DataOutputStream out) 
			throws IOException {
		CRC32 crc32 = new CRC32();
		crc32.update(chunkTypeBytes);
		if (data != null)
			crc32.update(data);
		long val = crc32.getValue();
		out.writeInt((int) val);
	}

	protected boolean verifyCRC(byte[] chunkTypeBytes, byte[] data, byte[] crcBytes) {

		int result = ByteBuffer.wrap(crcBytes).getInt();
		long crcInt = result & 0x00000000ffffffffL;

		CRC32 crc32 = new CRC32();
		crc32.update(chunkTypeBytes);
		if (data != null)
			crc32.update(data);
		long val = crc32.getValue();

		return val == crcInt;
	}

	/**
	 * simple signature generation method using SHA3-256
	 * 
	 * @param sc
	 * @param signer
	 * @param kmu
	 * @return
	 */
	protected String createSignature(SigningKeyContents sc, String signer, KMU kmu) {

		// create a signer using the signing key contents and sign
		TweetPepperSignature sig = new TweetPepperSHA3Signer(signer, sc)
				.addKMUBlocks(kmu).sign();

		// add the sig block to the KMU
		kmu.addBlock(sig.toBlock());

		// return the KMU in JSON representation
		StringWriter writer = new StringWriter();
		return new KMUOutputAdapter(kmu, false).writeTo(writer).toString();
	}

	/**
	 * Write a chunk to out
	 * 
	 * @param chunkTag
	 * @param data
	 * @param out
	 * @throws IOException
	 */

	protected void writeChunk(byte[] chunkTag, byte[] data, DataOutputStream out)
			throws IOException {
		out.writeInt(data.length); // 4 bytes of data length
		out.write(chunkTag); // our chunk 4 byte tag
		out.write(data); // the compressed data
		this.writeCRC(chunkTag, data, out);
	}

	/**
	 * read in a chunk, verify, and package data as a Chunk object
	 * @param din
	 * @return
	 * @throws IOException
	 */
	protected Chunk readChunk(DataInputStream din) throws IOException {
		
		// get the chunk length
		byte[] uIntBytes = new byte[4];
		din.readFully(uIntBytes, 0, 4);
		long uInt = uint(uIntBytes);

		// get the chunk type
		byte[] type = new byte[4];
		din.readFully(type, 0, 4);
		String chunkType = chunkType(type);

		// read the chunk data (if exists) and CRC
		byte[] data = null;
		byte[] crcBytes = new byte[4];

		if (uInt > 0) {
			data = new byte[(int) uInt];
			din.readFully(data, 0, (int) uInt);
			din.readFully(crcBytes, 0, 4);
		} else {
			din.readFully(crcBytes, 0, 4);
			data = null;
		}

		// verify CRC

		if (!verifyCRC(type, data, crcBytes)) {
			fail("crc failed for chunk " + chunkType);
		}
		
		return new Chunk(uIntBytes,uInt,type,chunkType,data,crcBytes);
	}
}

class Chunk {
	final byte[]uIntBytes;
	final long uInt;
	final byte[]type;
	final String chunkType;
	final byte[]data;
	final byte[]crcBytes;
	public Chunk(byte[]uIntBytes,long uInt, byte[]type,String chunkType, byte[] data, byte[] crcBytes) {
		super();
		this.uIntBytes=uIntBytes;
		this.uInt = uInt;
		this.type=type;
		this.chunkType = chunkType;
		this.data = data;
		this.crcBytes = crcBytes;
	}
}
