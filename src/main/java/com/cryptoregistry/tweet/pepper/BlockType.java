package com.cryptoregistry.tweet.pepper;

public enum BlockType {
	C, D, P, U, X, S, T;

	public static BlockType fromFlag(String flag) {
		switch (flag) {
		case "-C":
			return BlockType.C;
		case "-D":
			return BlockType.D;
		case "-P":
			return BlockType.P;
		case "-U":
			return BlockType.U;
		case "-X":
			return BlockType.X;
		case "-S":
			return BlockType.S;
		case "-T":
			return BlockType.T;
		default: { 
			throw new RuntimeException("Unknown block type: " + flag);
			}
		}
	}
}
