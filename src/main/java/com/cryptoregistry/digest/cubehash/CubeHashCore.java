// $Id: CubeHashCore.java 232 2010-06-17 14:19:24Z tp $

package com.cryptoregistry.digest.cubehash;

/**
 * This class implements the core operations for the CubeHash digest algorithm.
 *
 * <pre>
 * ==========================(LICENSE BEGIN)============================
 * 
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 * ===========================(LICENSE END)=============================
 * </pre>
 *
 * @version $Revision: 232 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public abstract class CubeHashCore extends DigestEngine {

	CubeHashCore() {
	}

	private int x0, x1, x2, x3, x4, x5, x6, x7;
	private int x8, x9, xa, xb, xc, xd, xe, xf;
	private int xg, xh, xi, xj, xk, xl, xm, xn;
	private int xo, xp, xq, xr, xs, xt, xu, xv;

	private final void inputBlock(byte[] data) {
		x0 ^= decodeLEInt(data, 0);
		x1 ^= decodeLEInt(data, 4);
		x2 ^= decodeLEInt(data, 8);
		x3 ^= decodeLEInt(data, 12);
		x4 ^= decodeLEInt(data, 16);
		x5 ^= decodeLEInt(data, 20);
		x6 ^= decodeLEInt(data, 24);
		x7 ^= decodeLEInt(data, 28);
	}

	private final void sixteenRounds() {
		for (int i = 0; i < 8; i++) {
			xg = x0 + xg;
			x0 = (x0 << 7) | (x0 >>> (32 - 7));
			xh = x1 + xh;
			x1 = (x1 << 7) | (x1 >>> (32 - 7));
			xi = x2 + xi;
			x2 = (x2 << 7) | (x2 >>> (32 - 7));
			xj = x3 + xj;
			x3 = (x3 << 7) | (x3 >>> (32 - 7));
			xk = x4 + xk;
			x4 = (x4 << 7) | (x4 >>> (32 - 7));
			xl = x5 + xl;
			x5 = (x5 << 7) | (x5 >>> (32 - 7));
			xm = x6 + xm;
			x6 = (x6 << 7) | (x6 >>> (32 - 7));
			xn = x7 + xn;
			x7 = (x7 << 7) | (x7 >>> (32 - 7));
			xo = x8 + xo;
			x8 = (x8 << 7) | (x8 >>> (32 - 7));
			xp = x9 + xp;
			x9 = (x9 << 7) | (x9 >>> (32 - 7));
			xq = xa + xq;
			xa = (xa << 7) | (xa >>> (32 - 7));
			xr = xb + xr;
			xb = (xb << 7) | (xb >>> (32 - 7));
			xs = xc + xs;
			xc = (xc << 7) | (xc >>> (32 - 7));
			xt = xd + xt;
			xd = (xd << 7) | (xd >>> (32 - 7));
			xu = xe + xu;
			xe = (xe << 7) | (xe >>> (32 - 7));
			xv = xf + xv;
			xf = (xf << 7) | (xf >>> (32 - 7));
			x8 ^= xg;
			x9 ^= xh;
			xa ^= xi;
			xb ^= xj;
			xc ^= xk;
			xd ^= xl;
			xe ^= xm;
			xf ^= xn;
			x0 ^= xo;
			x1 ^= xp;
			x2 ^= xq;
			x3 ^= xr;
			x4 ^= xs;
			x5 ^= xt;
			x6 ^= xu;
			x7 ^= xv;
			xi = x8 + xi;
			x8 = (x8 << 11) | (x8 >>> (32 - 11));
			xj = x9 + xj;
			x9 = (x9 << 11) | (x9 >>> (32 - 11));
			xg = xa + xg;
			xa = (xa << 11) | (xa >>> (32 - 11));
			xh = xb + xh;
			xb = (xb << 11) | (xb >>> (32 - 11));
			xm = xc + xm;
			xc = (xc << 11) | (xc >>> (32 - 11));
			xn = xd + xn;
			xd = (xd << 11) | (xd >>> (32 - 11));
			xk = xe + xk;
			xe = (xe << 11) | (xe >>> (32 - 11));
			xl = xf + xl;
			xf = (xf << 11) | (xf >>> (32 - 11));
			xq = x0 + xq;
			x0 = (x0 << 11) | (x0 >>> (32 - 11));
			xr = x1 + xr;
			x1 = (x1 << 11) | (x1 >>> (32 - 11));
			xo = x2 + xo;
			x2 = (x2 << 11) | (x2 >>> (32 - 11));
			xp = x3 + xp;
			x3 = (x3 << 11) | (x3 >>> (32 - 11));
			xu = x4 + xu;
			x4 = (x4 << 11) | (x4 >>> (32 - 11));
			xv = x5 + xv;
			x5 = (x5 << 11) | (x5 >>> (32 - 11));
			xs = x6 + xs;
			x6 = (x6 << 11) | (x6 >>> (32 - 11));
			xt = x7 + xt;
			x7 = (x7 << 11) | (x7 >>> (32 - 11));
			xc ^= xi;
			xd ^= xj;
			xe ^= xg;
			xf ^= xh;
			x8 ^= xm;
			x9 ^= xn;
			xa ^= xk;
			xb ^= xl;
			x4 ^= xq;
			x5 ^= xr;
			x6 ^= xo;
			x7 ^= xp;
			x0 ^= xu;
			x1 ^= xv;
			x2 ^= xs;
			x3 ^= xt;

			xj = xc + xj;
			xc = (xc << 7) | (xc >>> (32 - 7));
			xi = xd + xi;
			xd = (xd << 7) | (xd >>> (32 - 7));
			xh = xe + xh;
			xe = (xe << 7) | (xe >>> (32 - 7));
			xg = xf + xg;
			xf = (xf << 7) | (xf >>> (32 - 7));
			xn = x8 + xn;
			x8 = (x8 << 7) | (x8 >>> (32 - 7));
			xm = x9 + xm;
			x9 = (x9 << 7) | (x9 >>> (32 - 7));
			xl = xa + xl;
			xa = (xa << 7) | (xa >>> (32 - 7));
			xk = xb + xk;
			xb = (xb << 7) | (xb >>> (32 - 7));
			xr = x4 + xr;
			x4 = (x4 << 7) | (x4 >>> (32 - 7));
			xq = x5 + xq;
			x5 = (x5 << 7) | (x5 >>> (32 - 7));
			xp = x6 + xp;
			x6 = (x6 << 7) | (x6 >>> (32 - 7));
			xo = x7 + xo;
			x7 = (x7 << 7) | (x7 >>> (32 - 7));
			xv = x0 + xv;
			x0 = (x0 << 7) | (x0 >>> (32 - 7));
			xu = x1 + xu;
			x1 = (x1 << 7) | (x1 >>> (32 - 7));
			xt = x2 + xt;
			x2 = (x2 << 7) | (x2 >>> (32 - 7));
			xs = x3 + xs;
			x3 = (x3 << 7) | (x3 >>> (32 - 7));
			x4 ^= xj;
			x5 ^= xi;
			x6 ^= xh;
			x7 ^= xg;
			x0 ^= xn;
			x1 ^= xm;
			x2 ^= xl;
			x3 ^= xk;
			xc ^= xr;
			xd ^= xq;
			xe ^= xp;
			xf ^= xo;
			x8 ^= xv;
			x9 ^= xu;
			xa ^= xt;
			xb ^= xs;
			xh = x4 + xh;
			x4 = (x4 << 11) | (x4 >>> (32 - 11));
			xg = x5 + xg;
			x5 = (x5 << 11) | (x5 >>> (32 - 11));
			xj = x6 + xj;
			x6 = (x6 << 11) | (x6 >>> (32 - 11));
			xi = x7 + xi;
			x7 = (x7 << 11) | (x7 >>> (32 - 11));
			xl = x0 + xl;
			x0 = (x0 << 11) | (x0 >>> (32 - 11));
			xk = x1 + xk;
			x1 = (x1 << 11) | (x1 >>> (32 - 11));
			xn = x2 + xn;
			x2 = (x2 << 11) | (x2 >>> (32 - 11));
			xm = x3 + xm;
			x3 = (x3 << 11) | (x3 >>> (32 - 11));
			xp = xc + xp;
			xc = (xc << 11) | (xc >>> (32 - 11));
			xo = xd + xo;
			xd = (xd << 11) | (xd >>> (32 - 11));
			xr = xe + xr;
			xe = (xe << 11) | (xe >>> (32 - 11));
			xq = xf + xq;
			xf = (xf << 11) | (xf >>> (32 - 11));
			xt = x8 + xt;
			x8 = (x8 << 11) | (x8 >>> (32 - 11));
			xs = x9 + xs;
			x9 = (x9 << 11) | (x9 >>> (32 - 11));
			xv = xa + xv;
			xa = (xa << 11) | (xa >>> (32 - 11));
			xu = xb + xu;
			xb = (xb << 11) | (xb >>> (32 - 11));
			x0 ^= xh;
			x1 ^= xg;
			x2 ^= xj;
			x3 ^= xi;
			x4 ^= xl;
			x5 ^= xk;
			x6 ^= xn;
			x7 ^= xm;
			x8 ^= xp;
			x9 ^= xo;
			xa ^= xr;
			xb ^= xq;
			xc ^= xt;
			xd ^= xs;
			xe ^= xv;
			xf ^= xu;
		}
	}

	/**
	 * Encode the 32-bit word {@code val} into the array {@code buf} at offset
	 * {@code off}, in little-endian convention (least significant byte first).
	 *
	 * @param val
	 *            the value to encode
	 * @param buf
	 *            the destination buffer
	 * @param off
	 *            the destination offset
	 */
	private static final void encodeLEInt(int val, byte[] buf, int off) {
		buf[off + 0] = (byte) val;
		buf[off + 1] = (byte) (val >>> 8);
		buf[off + 2] = (byte) (val >>> 16);
		buf[off + 3] = (byte) (val >>> 24);
	}

	/**
	 * Decode a 32-bit little-endian word from the array {@code buf} at offset
	 * {@code off}.
	 *
	 * @param buf
	 *            the source buffer
	 * @param off
	 *            the source offset
	 * @return the decoded value
	 */
	private static final int decodeLEInt(byte[] buf, int off) {
		return (buf[off + 0] & 0xFF) | ((buf[off + 1] & 0xFF) << 8)
				| ((buf[off + 2] & 0xFF) << 16) | ((buf[off + 3] & 0xFF) << 24);
	}

	/** @see DigestEngine */
	protected void engineReset() {
		doReset();
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data) {
		inputBlock(data);
		sixteenRounds();
	}

	/** @see DigestEngine */
	protected void doPadding(byte[] out, int off) {
		int ptr = flush();
		byte[] buf = getBlockBuffer();
		buf[ptr++] = (byte) 0x80;
		while (ptr < 32)
			buf[ptr++] = 0x00;
		inputBlock(buf);
		sixteenRounds();
		xv ^= 1;
		for (int j = 0; j < 10; j++)
			sixteenRounds();
		int dlen = getDigestLength();
		encodeLEInt(x0, out, off + 0);
		encodeLEInt(x1, out, off + 4);
		encodeLEInt(x2, out, off + 8);
		encodeLEInt(x3, out, off + 12);
		encodeLEInt(x4, out, off + 16);
		encodeLEInt(x5, out, off + 20);
		encodeLEInt(x6, out, off + 24);
		if (dlen == 28)
			return;
		encodeLEInt(x7, out, off + 28);
		if (dlen == 32)
			return;
		encodeLEInt(x8, out, off + 32);
		encodeLEInt(x9, out, off + 36);
		encodeLEInt(xa, out, off + 40);
		encodeLEInt(xb, out, off + 44);
		if (dlen == 48)
			return;
		encodeLEInt(xc, out, off + 48);
		encodeLEInt(xd, out, off + 52);
		encodeLEInt(xe, out, off + 56);
		encodeLEInt(xf, out, off + 60);
	}

	/** @see DigestEngine */
	protected void doInit() {
		doReset();
	}

	/**
	 * Get the initial values.
	 *
	 * @return the IV
	 */
	abstract int[] getIV();

	/** @see DigestEngine */
	public int getInternalBlockLength() {
		return 32;
	}

	/** @see Digest */
	public int getBlockLength() {
		/*
		 * From the CubeHash specification:
		 * 
		 * << Applications such as HMAC that pad to a full block of SHA-h input
		 * are required to pad to a full minimal integral number of b-byte
		 * blocks for CubeHashr/b-h. >>
		 * 
		 * Here, b = 32.
		 */
		return -32;
	}

	private final void doReset() {
		int[] iv = getIV();
		x0 = iv[0];
		x1 = iv[1];
		x2 = iv[2];
		x3 = iv[3];
		x4 = iv[4];
		x5 = iv[5];
		x6 = iv[6];
		x7 = iv[7];
		x8 = iv[8];
		x9 = iv[9];
		xa = iv[10];
		xb = iv[11];
		xc = iv[12];
		xd = iv[13];
		xe = iv[14];
		xf = iv[15];
		xg = iv[16];
		xh = iv[17];
		xi = iv[18];
		xj = iv[19];
		xk = iv[20];
		xl = iv[21];
		xm = iv[22];
		xn = iv[23];
		xo = iv[24];
		xp = iv[25];
		xq = iv[26];
		xr = iv[27];
		xs = iv[28];
		xt = iv[29];
		xu = iv[30];
		xv = iv[31];
	}

	/** @see DigestEngine */
	protected Digest copyState(CubeHashCore dst) {
		dst.x0 = x0;
		dst.x1 = x1;
		dst.x2 = x2;
		dst.x3 = x3;
		dst.x4 = x4;
		dst.x5 = x5;
		dst.x6 = x6;
		dst.x7 = x7;
		dst.x8 = x8;
		dst.x9 = x9;
		dst.xa = xa;
		dst.xb = xb;
		dst.xc = xc;
		dst.xd = xd;
		dst.xe = xe;
		dst.xf = xf;
		dst.xg = xg;
		dst.xh = xh;
		dst.xi = xi;
		dst.xj = xj;
		dst.xk = xk;
		dst.xl = xl;
		dst.xm = xm;
		dst.xn = xn;
		dst.xo = xo;
		dst.xp = xp;
		dst.xq = xq;
		dst.xr = xr;
		dst.xs = xs;
		dst.xt = xt;
		dst.xu = xu;
		dst.xv = xv;
		return super.copyState(dst);
	}

	/** @see Digest */
	public String toString() {
		return "CubeHash-" + (getDigestLength() << 3);
	}
}


/**
* <p>
* This interface documents the API for a hash function. This interface somewhat
* mimics the standard {@code java.security.MessageDigest} class. We do not
* extend that class in order to provide compatibility with reduced Java
* implementations such as J2ME. Implementing a {@code java.security.Provider}
* compatible with Sun's JCA ought to be easy.
* </p>
*
* <p>
* A {@code Digest} object maintains a running state for a hash function
* computation. Data is inserted with {@code update()} calls; the result is
* obtained from a {@code digest()} method (where some final data can be
* inserted as well). When a digest output has been produced, the objet is
* automatically resetted, and can be used immediately for another digest
* operation. The state of a computation can be cloned with the {@link #copy}
* method; this can be used to get a partial hash result without interrupting
* the complete computation.
* </p>
*
* <p>
* {@code Digest} objects are stateful and hence not thread-safe; however,
* distinct {@code Digest} objects can be accessed concurrently without any
* problem.
* </p>
*
* <pre>
* ==========================(LICENSE BEGIN)============================
* 
* Copyright (c) 2007-2010  Projet RNRT SAPHIR
* 
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
* 
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* ===========================(LICENSE END)=============================
* </pre>
*
* @version $Revision: 232 $
* @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
*/

interface Digest {

	/**
	 * Insert one more input data byte.
	 *
	 * @param in
	 *            the input byte
	 */
	public void update(byte in);

	/**
	 * Insert some more bytes.
	 *
	 * @param inbuf
	 *            the data bytes
	 */
	public void update(byte[] inbuf);

	/**
	 * Insert some more bytes.
	 *
	 * @param inbuf
	 *            the data buffer
	 * @param off
	 *            the data offset in {@code inbuf}
	 * @param len
	 *            the data length (in bytes)
	 */
	public void update(byte[] inbuf, int off, int len);

	/**
	 * Finalize the current hash computation and return the hash value in a
	 * newly-allocated array. The object is resetted.
	 *
	 * @return the hash output
	 */
	public byte[] digest();

	/**
	 * Input some bytes, then finalize the current hash computation and return
	 * the hash value in a newly-allocated array. The object is resetted.
	 *
	 * @param inbuf
	 *            the input data
	 * @return the hash output
	 */
	public byte[] digest(byte[] inbuf);

	/**
	 * Finalize the current hash computation and store the hash value in the
	 * provided output buffer. The {@code len} parameter contains the maximum
	 * number of bytes that should be written; no more bytes than the natural
	 * hash function output length will be produced. If {@code len} is smaller
	 * than the natural hash output length, the hash output is truncated to its
	 * first {@code len} bytes. The object is resetted.
	 *
	 * @param outbuf
	 *            the output buffer
	 * @param off
	 *            the output offset within {@code outbuf}
	 * @param len
	 *            the requested hash output length (in bytes)
	 * @return the number of bytes actually written in {@code outbuf}
	 */
	public int digest(byte[] outbuf, int off, int len);

	/**
	 * Get the natural hash function output length (in bytes).
	 *
	 * @return the digest output length (in bytes)
	 */
	public int getDigestLength();

	/**
	 * Reset the object: this makes it suitable for a new hash computation. The
	 * current computation, if any, is discarded.
	 */
	public void reset();

	/**
	 * Clone the current state. The returned object evolves independently of
	 * this object.
	 *
	 * @return the clone
	 */
	public Digest copy();

	/**
	 * <p>
	 * Return the "block length" for the hash function. This value is naturally
	 * defined for iterated hash functions (Merkle-Damgard). It is used in HMAC
	 * (that's what the <a href="http://tools.ietf.org/html/rfc2104">HMAC
	 * specification</a> names the "{@code B}" parameter).
	 * </p>
	 *
	 * <p>
	 * If the function is "block-less" then this function may return {@code -n}
	 * where {@code n} is an integer such that the block length for HMAC ("
	 * {@code B}") will be inferred from the key length, by selecting the
	 * smallest multiple of {@code n} which is no smaller than the key length.
	 * For instance, for the Fugue-xxx hash functions, this function returns -4:
	 * the virtual block length B is the HMAC key length, rounded up to the next
	 * multiple of 4.
	 * </p>
	 *
	 * @return the internal block length (in bytes), or {@code -n}
	 */
	public int getBlockLength();

	/**
	 * <p>
	 * Get the display name for this function (e.g. {@code "SHA-1"} for SHA-1).
	 * </p>
	 *
	 * @see Object
	 */
	public String toString();
}

/**
 * <p>
 * This class is a template which can be used to implement hash functions. It
 * takes care of some of the API, and also provides an internal data buffer
 * whose length is equal to the hash function internal block length.
 * </p>
 *
 * <p>
 * Classes which use this template MUST provide a working
 * {@link #getBlockLength} method even before initialization (alternatively,
 * they may define a custom {@link #getInternalBlockLength} which does not call
 * {@link #getBlockLength}. The {@link #getDigestLength} should also be
 * operational from the beginning, but it is acceptable that it returns 0 while
 * the {@link #doInit} method has not been called yet.
 * </p>
 *
 * <pre>
 * ==========================(LICENSE BEGIN)============================
 * 
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 * ===========================(LICENSE END)=============================
 * </pre>
 *
 * @version $Revision: 229 $
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

abstract class DigestEngine implements Digest {

	/**
	 * Reset the hash algorithm state.
	 */
	protected abstract void engineReset();

	/**
	 * Process one block of data.
	 *
	 * @param data
	 *            the data block
	 */
	protected abstract void processBlock(byte[] data);

	/**
	 * Perform the final padding and store the result in the provided buffer.
	 * This method shall call {@link #flush} and then {@link #update} with the
	 * appropriate padding data in order to get the full input data.
	 *
	 * @param buf
	 *            the output buffer
	 * @param off
	 *            the output offset
	 */
	protected abstract void doPadding(byte[] buf, int off);

	/**
	 * This function is called at object creation time; the implementation
	 * should use it to perform initialization tasks. After this method is
	 * called, the implementation should be ready to process data or
	 * meaningfully honour calls such as {@link #getDigestLength}</code>.
	 */
	protected abstract void doInit();

	private int digestLen, blockLen, inputLen;
	private byte[] inputBuf, outputBuf;
	private long blockCount;

	/**
	 * Instantiate the engine.
	 */
	public DigestEngine() {
		doInit();
		digestLen = getDigestLength();
		blockLen = getInternalBlockLength();
		inputBuf = new byte[blockLen];
		outputBuf = new byte[digestLen];
		inputLen = 0;
		blockCount = 0;
	}

	private void adjustDigestLen() {
		if (digestLen == 0) {
			digestLen = getDigestLength();
			outputBuf = new byte[digestLen];
		}
	}

	/** @see Digest */
	public byte[] digest() {
		adjustDigestLen();
		byte[] result = new byte[digestLen];
		digest(result, 0, digestLen);
		return result;
	}

	/** @see Digest */
	public byte[] digest(byte[] input) {
		update(input, 0, input.length);
		return digest();
	}

	/** @see Digest */
	public int digest(byte[] buf, int offset, int len) {
		adjustDigestLen();
		if (len >= digestLen) {
			doPadding(buf, offset);
			reset();
			return digestLen;
		} else {
			doPadding(outputBuf, 0);
			System.arraycopy(outputBuf, 0, buf, offset, len);
			reset();
			return len;
		}
	}

	/** @see Digest */
	public void reset() {
		engineReset();
		inputLen = 0;
		blockCount = 0;
	}

	/** @see Digest */
	public void update(byte input) {
		inputBuf[inputLen++] = (byte) input;
		if (inputLen == blockLen) {
			processBlock(inputBuf);
			blockCount++;
			inputLen = 0;
		}
	}

	/** @see Digest */
	public void update(byte[] input) {
		update(input, 0, input.length);
	}

	/** @see Digest */
	public void update(byte[] input, int offset, int len) {
		while (len > 0) {
			int copyLen = blockLen - inputLen;
			if (copyLen > len)
				copyLen = len;
			System.arraycopy(input, offset, inputBuf, inputLen, copyLen);
			offset += copyLen;
			inputLen += copyLen;
			len -= copyLen;
			if (inputLen == blockLen) {
				processBlock(inputBuf);
				blockCount++;
				inputLen = 0;
			}
		}
	}

	/**
	 * Get the internal block length. This is the length (in bytes) of the array
	 * which will be passed as parameter to {@link #processBlock}. The default
	 * implementation of this method calls {@link #getBlockLength} and returns
	 * the same value. Overriding this method is useful when the advertised
	 * block length (which is used, for instance, by HMAC) is suboptimal with
	 * regards to internal buffering needs.
	 *
	 * @return the internal block length (in bytes)
	 */
	protected int getInternalBlockLength() {
		return getBlockLength();
	}

	/**
	 * Flush internal buffers, so that less than a block of data may at most be
	 * upheld.
	 *
	 * @return the number of bytes still unprocessed after the flush
	 */
	protected final int flush() {
		return inputLen;
	}

	/**
	 * Get a reference to an internal buffer with the same size than a block.
	 * The contents of that buffer are defined only immediately after a call to
	 * {@link #flush()}: if {@link #flush()} return the value {@code n}, then
	 * the first {@code n} bytes of the array returned by this method are the
	 * {@code n} bytes of input data which are still unprocessed. The values of
	 * the remaining bytes are undefined and may be altered at will.
	 *
	 * @return a block-sized internal buffer
	 */
	protected final byte[] getBlockBuffer() {
		return inputBuf;
	}

	/**
	 * Get the "block count": this is the number of times the
	 * {@link #processBlock} method has been invoked for the current hash
	 * operation. That counter is incremented <em>after</em> the call to
	 * {@link #processBlock}.
	 *
	 * @return the block count
	 */
	protected long getBlockCount() {
		return blockCount;
	}

	/**
	 * This function copies the internal buffering state to some other instance
	 * of a class extending {@code DigestEngine}. It returns a reference to the
	 * copy. This method is intended to be called by the implementation of the
	 * {@link #copy} method.
	 *
	 * @param dest
	 *            the copy
	 * @return the value {@code dest}
	 */
	protected Digest copyState(DigestEngine dest) {
		dest.inputLen = inputLen;
		dest.blockCount = blockCount;
		System.arraycopy(inputBuf, 0, dest.inputBuf, 0, inputBuf.length);
		adjustDigestLen();
		dest.adjustDigestLen();
		System.arraycopy(outputBuf, 0, dest.outputBuf, 0, outputBuf.length);
		return dest;
	}
}


