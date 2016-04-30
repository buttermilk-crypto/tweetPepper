package com.cryptoregistry.tweet.pepper;

public enum BlockType {
	C, D, E, P, U, X, S, T;

	public static BlockType fromFlag(String flag) {
		switch (flag) {
		case "-C":
			return BlockType.C; // contact
		case "-D":
			return BlockType.D; // data
		case "-E":
			return BlockType.E; // encrypt block (data in encrypted form or data ref pointing to such)
		case "-P":
			return BlockType.P; // for publication or export key
		case "-U":
			return BlockType.U; // unprotected or open confidential key contents
		case "-X":
			return BlockType.X; // confidential key but encrypted contents
		case "-S":
			return BlockType.S; // signature
		case "-T":
			return BlockType.T; // transaction
		default: { 
			throw new RuntimeException("Unknown block type: " + flag);
			}
		}
	}
}
