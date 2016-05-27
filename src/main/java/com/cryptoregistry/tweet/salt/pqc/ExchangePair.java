package com.cryptoregistry.tweet.salt.pqc;

/**
 * Pair for a value exchange algorithm where the responding party has no private
 * key, such as NewHope.
 */
public class ExchangePair {
	private final NHKeyForPublication publicKey;
	private final byte[] shared;

	/**
	 * Base constructor.
	 *
	 * @param publicKey
	 *            The responding party's public key.
	 * @param shared
	 *            the calculated shared value.
	 */
	public ExchangePair(NHKeyForPublication forPublication, byte[] shared) {
		this.publicKey = forPublication;
		this.shared = shared;
	}

	/**
	 * Return the responding party's public key.
	 *
	 * @return the public key calculated for the exchange.
	 */
	public NHKeyForPublication getPublicKey() {
		return publicKey;
	}

	/**
	 * Return the shared value calculated with public key.
	 *
	 * @return the shared value.
	 */
	public byte[] getSharedValue() {
		return shared;
	}
}
