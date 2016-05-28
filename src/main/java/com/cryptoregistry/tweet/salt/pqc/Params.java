/*
 Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
*/
package com.cryptoregistry.tweet.salt.pqc;

final class Params {
	static final int N = 1024;
	static final int K = 16; /* used in sampler */
	static final int Q = 12289;

	static final int POLY_BYTES = 1792;
	static final int REC_BYTES = 256;
	static final int SEED_BYTES = 32;
}
