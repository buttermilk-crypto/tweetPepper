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

package com.cryptoregistry.tweet.pepper;

public enum BlockType {
	A, C, D, E, P, U, X, S, T;

	public static BlockType fromFlag(String flag) {
		switch (flag) {
		case "-A":
			return BlockType.A; // for key agreement or key exchange as in NewHope
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
