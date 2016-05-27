package com.cryptoregistry.tweet.salt.pqc;

import com.cryptoregistry.digest.sha3.SHAKEDigest;

class Poly {

	final NTT ntt;

	public Poly() {
		ntt = new NTT();
	}

	void add(short[] x, short[] y, short[] z) {
		for (int i = 0; i < Params.N; ++i) {
			z[i] = Reduce.barrett((short) (x[i] + y[i]));
		}
	}

	void fromBytes(short[] r, byte[] a) {
		for (int i = 0; i < Params.N / 4; ++i) {
			int j = 7 * i;
			int a0 = a[j + 0] & 0xFF, a1 = a[j + 1] & 0xFF, a2 = a[j + 2] & 0xFF, a3 = a[j + 3] & 0xFF, a4 = a[j + 4] & 0xFF, a5 = a[j + 5] & 0xFF, a6 = a[j + 6] & 0xFF;

			int k = 4 * i;
			r[k + 0] = (short) (a0 | ((a1 & 0x3F) << 8));
			r[k + 1] = (short) ((a1 >>> 6) | (a2 << 2) | ((a3 & 0x0F) << 10));
			r[k + 2] = (short) ((a3 >>> 4) | (a4 << 4) | ((a5 & 0x03) << 12));
			r[k + 3] = (short) ((a5 >>> 2) | (a6 << 6));
		}
	}

	void fromNTT(short[] r) {
		ntt.bitReverse(r);
		ntt.core(r, Precomp.OMEGAS_INV_MONTGOMERY);
		ntt.mulCoefficients(r, Precomp.PSIS_INV_MONTGOMERY);
	}

	void getNoise(short[] r, byte[] seed, byte nonce) {
		byte[] iv = new byte[8];
		iv[0] = nonce;

		byte[] buf = new byte[4 * Params.N];
		new ChaCha20().process(seed, iv, buf, 0, buf.length);

		for (int i = 0; i < Params.N; ++i) {
			int t = bigEndianToInt(buf, i * 4);
			// r[i] = (short)(bitCount(t) + Params.Q - Params.K);

			int d = 0;
			for (int j = 0; j < 8; ++j) {
				d += (t >> j) & 0x01010101;
			}
			int a = ((d >>> 24) + (d >>> 0)) & 0xFF;
			int b = ((d >>> 16) + (d >>> 8)) & 0xFF;
			r[i] = (short) (a + Params.Q - b);
		}
	}

	void pointWise(short[] x, short[] y, short[] z) {
		for (int i = 0; i < Params.N; ++i) {
			int xi = x[i] & 0xFFFF, yi = y[i] & 0xFFFF;
			short t = Reduce.montgomery(3186 * yi); // t is now in Montgomery
													// domain
			z[i] = Reduce.montgomery(xi * (t & 0xFFFF)); // z[i] is back in
															// normal domain
		}
	}

	void toBytes(byte[] r, short[] p) {
		for (int i = 0; i < Params.N / 4; ++i) {
			int j = 4 * i;

			// Make sure that coefficients are in [0,q]
			short t0 = normalize(p[j + 0]);
			short t1 = normalize(p[j + 1]);
			short t2 = normalize(p[j + 2]);
			short t3 = normalize(p[j + 3]);

			int k = 7 * i;
			r[k + 0] = (byte) t0;
			r[k + 1] = (byte) ((t0 >> 8) | (t1 << 6));
			r[k + 2] = (byte) (t1 >> 2);
			r[k + 3] = (byte) ((t1 >> 10) | (t2 << 4));
			r[k + 4] = (byte) (t2 >> 4);
			r[k + 5] = (byte) ((t2 >> 12) | (t3 << 2));
			r[k + 6] = (byte) (t3 >> 6);
		}
	}

	void toNTT(short[] r) {
		ntt.mulCoefficients(r, Precomp.PSIS_BITREV_MONTGOMERY);
		ntt.core(r, Precomp.OMEGAS_MONTGOMERY);
	}

	void uniform(short[] a, byte[] seed) {
		SHAKEDigest xof = new SHAKEDigest(128);
		xof.update(seed, 0, seed.length);

		int pos = 0;
		for (;;) {
			byte[] output = new byte[256];
			xof.doOutput(output, 0, output.length);

			for (int i = 0; i < output.length; i += 2) {
				int val = (output[i] & 0xFF) | ((output[i + 1] & 0xFF) << 8);
				val &= 0x3FFF;
				if (val < Params.Q) {
					a[pos++] = (short) val;
					if (pos == Params.N) {
						return;
					}
				}
			}
		}
	}

	private short normalize(short x) {
		int t = Reduce.barrett(x);
		int m = t - Params.Q;
		int c = m >> 31;
		t = m ^ ((t ^ m) & c);
		return (short) t;
	}

	// from Pack

	public int bigEndianToInt(byte[] bs, int off) {
		int n = bs[off] << 24;
		n |= (bs[++off] & 0xff) << 16;
		n |= (bs[++off] & 0xff) << 8;
		n |= (bs[++off] & 0xff);
		return n;
	}
}
