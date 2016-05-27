package com.cryptoregistry.tweet.salt.pqc;

import java.security.SecureRandom;

import com.cryptoregistry.digest.sha3.SHA3Digest;

/**
 * This implementation is based heavily on the C reference implementation from
 * https://cryptojedi.org/crypto/index.shtml.
 */
public class NewHope {

	private static final boolean STATISTICAL_TEST = false;
	public static final int AGREEMENT_SIZE = 32;
	public static final int POLY_SIZE = Params.N;
	public static final int SENDA_BYTES = Params.POLY_BYTES + Params.SEED_BYTES;
	public static final int SENDB_BYTES = Params.POLY_BYTES + Params.REC_BYTES;

	private Poly poly;
	private ErrorCorrection err;

	public NewHope() {
		super();
		poly = new Poly();
		err = new ErrorCorrection();
	}

	public NHKeyContents generateKeys(SecureRandom rand) {
		byte[] pubData = new byte[NewHope.SENDA_BYTES];
		short[] secData = new short[NewHope.POLY_SIZE];

		keygen(rand, pubData, secData);
		return new NHKeyContents(pubData, secData);
	}

	public ExchangePair generateExchange(SecureRandom rand,
			NHKeyForPublication senderPublicKey) {

		byte[] sharedValue = new byte[NewHope.AGREEMENT_SIZE];
		byte[] publicKeyValue = new byte[NewHope.SENDB_BYTES];

		sharedB(rand, sharedValue, publicKeyValue, senderPublicKey.pubData);

		return new ExchangePair(new NHKeyForPublication(publicKeyValue),
				sharedValue);
	}

	public byte[] calculateAgreement(NHKeyContents contents,
			NHKeyForPublication otherPublicKey) {

		byte[] sharedValue = new byte[NewHope.AGREEMENT_SIZE];

		sharedA(sharedValue, contents.secData, otherPublicKey.pubData);

		return sharedValue;
	}

	void keygen(SecureRandom rand, byte[] send, short[] sk) {
		byte[] seed = new byte[Params.SEED_BYTES];
		rand.nextBytes(seed);

		short[] a = new short[Params.N];
		generateA(a, seed);

		byte[] noiseSeed = new byte[32];
		rand.nextBytes(noiseSeed);

		poly.getNoise(sk, noiseSeed, (byte) 0);
		poly.toNTT(sk);

		short[] e = new short[Params.N];
		poly.getNoise(e, noiseSeed, (byte) 1);
		poly.toNTT(e);

		short[] r = new short[Params.N];
		poly.pointWise(a, sk, r);

		short[] pk = new short[Params.N];
		poly.add(r, e, pk);

		encodeA(send, pk, seed);
	}

	public void sharedB(SecureRandom rand, byte[] sharedKey, byte[] send,
			byte[] received) {
		short[] pkA = new short[Params.N];
		byte[] seed = new byte[Params.SEED_BYTES];
		decodeA(pkA, seed, received);

		short[] a = new short[Params.N];
		generateA(a, seed);

		byte[] noiseSeed = new byte[32];
		rand.nextBytes(noiseSeed);

		short[] sp = new short[Params.N];
		poly.getNoise(sp, noiseSeed, (byte) 0);
		poly.toNTT(sp);

		short[] ep = new short[Params.N];
		poly.getNoise(ep, noiseSeed, (byte) 1);
		poly.toNTT(ep);

		short[] bp = new short[Params.N];
		poly.pointWise(a, sp, bp);
		poly.add(bp, ep, bp);

		short[] v = new short[Params.N];
		poly.pointWise(pkA, sp, v);
		poly.fromNTT(v);

		short[] epp = new short[Params.N];
		poly.getNoise(epp, noiseSeed, (byte) 2);
		poly.add(v, epp, v);

		short[] c = new short[Params.N];
		err.helpRec(c, v, noiseSeed, (byte) 3);

		encodeB(send, bp, c);

		err.rec(sharedKey, v, c);

		if (!STATISTICAL_TEST) {
			sha3(sharedKey);
		}
	}

	public void sharedA(byte[] sharedKey, short[] sk, byte[] received) {
		short[] bp = new short[Params.N];
		short[] c = new short[Params.N];
		decodeB(bp, c, received);

		short[] v = new short[Params.N];
		poly.pointWise(sk, bp, v);
		poly.fromNTT(v);

		err.rec(sharedKey, v, c);

		if (!STATISTICAL_TEST) {
			sha3(sharedKey);
		}
	}

	void decodeA(short[] pk, byte[] seed, byte[] r) {
		poly.fromBytes(pk, r);
		System.arraycopy(r, Params.POLY_BYTES, seed, 0, Params.SEED_BYTES);
	}

	void decodeB(short[] b, short[] c, byte[] r) {
		poly.fromBytes(b, r);

		for (int i = 0; i < Params.N / 4; ++i) {
			int j = 4 * i;
			int ri = r[Params.POLY_BYTES + i] & 0xFF;
			c[j + 0] = (short) (ri & 0x03);
			c[j + 1] = (short) ((ri >>> 2) & 0x03);
			c[j + 2] = (short) ((ri >>> 4) & 0x03);
			c[j + 3] = (short) (ri >>> 6);
		}
	}

	void encodeA(byte[] r, short[] pk, byte[] seed) {
		poly.toBytes(r, pk);
		System.arraycopy(seed, 0, r, Params.POLY_BYTES, Params.SEED_BYTES);
	}

	void encodeB(byte[] r, short[] b, short[] c) {
		poly.toBytes(r, b);

		for (int i = 0; i < Params.N / 4; ++i) {
			int j = 4 * i;
			r[Params.POLY_BYTES + i] = (byte) (c[j] | (c[j + 1] << 2)
					| (c[j + 2] << 4) | (c[j + 3] << 6));
		}
	}

	void generateA(short[] a, byte[] seed) {
		poly.uniform(a, seed);
	}

	void sha3(byte[] sharedKey) {
		SHA3Digest d = new SHA3Digest(256);
		d.update(sharedKey, 0, 32);
		d.doFinal(sharedKey, 0);
	}
}
