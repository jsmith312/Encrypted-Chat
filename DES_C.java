/**
 * @authors Chris Pawlik, Jordan Smith
 * CSc 466
 * Assignment 5 Part C
 * 
 */
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.security.SecureRandom;
import java.util.BitSet;

import java.util.BitSet;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64.Encoder;

import gnu.getopt.Getopt;

public class DES_C {
	public static boolean DEBUG = false;
	public static int K_BITS = 64;
	public static BitSet K_BITSET;
	public static BitSet[] C;
	public static BitSet[] D;
	public static BitSet[] K = new BitSet[16];
	public static int Kp_BITS = 56;
	public static BitSet Kp_BITSET;
	public static String hex;
	public static BitSet IV;
	public static boolean FULL_BLOCK = false;
	public static String message;
	public static String new_message = "";
	public static String key;
	
	public static String decrypt(String keyHex, String m) {
		new_message = "";
		K_BITSET = hexToBinary(keyHex, 64);
		String[] lines = m.split("\n");
		String line = "";
		
		IV = hexToBinary(lines[0], 64);
		String encryptedText;
		String IVStr = "";
		
		for(int i = 1; i < lines.length; i++){
			line = lines[i];
			encryptedText = DES_decrypt(IVStr, line);
			if (!FULL_BLOCK) {
				new_message += (encryptedText + "\n");
			} else {
				new_message += encryptedText;
			}
		}
			
		FULL_BLOCK = false;
		return new_message;
	}

	/**
	 * DES_decrypt():
	 * 
	 * @param line
	 */
	private static String DES_decrypt(String iVStr, String line) {
		permute56bits();
		genKeys();
		KKeys();

		// prepare message
		BitSet M;
		String result = "";

		for (int i = 0; i < line.length(); i += 64) {
			M = hexToBinary(line, 64);
			result += messageDecrypt(M);
		}
		return result;
	}

	/**
	 * encrypt():
	 * 
	 * @param keyStr
	 *            , inputFile, outputFile
	 * 
	 * Prepend 64 bit IV
	 */
	public static String encrypt(String keyHex, String m) {
		new_message = "";
		K_BITSET = hexToBinary(keyHex, 64);
		message = m;
		key = keyHex;
		genIV();
		new_message += hexConv(IV, K_BITS) + "\n";
		new_message += DES_encrypt();	
		return new_message;
	}

	/**
	 * DES_encrypt():
	 * 
	 * @param line
	 * 
	 *            Takes in a full line of cleartext and converts to encrypted
	 *            hex. Calls permute56bits(), genKeys() and KKeys() to generate
	 *            subkeys from input key.
	 */
	private static String DES_encrypt() {
		boolean notFullBlock = false;
		String bin = "";
		permute56bits();

		genKeys();
		KKeys();

		// prepare message
		BitSet M;
		byte[] bytes = message.getBytes();
		// leading zeros
		String[] array = { "", "0", "00", "000", "0000", "00000", "000000",
				"0000000" };
		String str = "", bits = "", result = "";
		int diff = 0;

		// convert line to bit string
		for (int i = 0; i < message.length(); i++) {
			str = Integer.toBinaryString(bytes[i]);
			diff = (8 - str.length());
			for (int j = 0; j < diff; j++) {
				bits += "0";
			}
			bits += str;
		}
		// If last M in line has less than 64bits append 0's
		int size = bits.length(), j = (64 - (size % 64)), k = 0;
		int used = (size % 64) / 8;

		int unused = (8 - used);
		if (unused > 0 && used != 0) {
			for (int i = 0; i < 8 * (unused - 1); i++) {
				bits += "0";
			}
			bin = "" + unused;
			bytes = bin.getBytes();
			str = Integer.toBinaryString(bytes[0]);
			diff = (8 - str.length());
			for (int n = 0; n < diff; n++) {
				bits += "0";
			}
			bits += str;
		}
		size = (bits.length() / 64);
		// encrypt each message-block of line
		for (int i = 0; i < size; i++) {
			M = new BitSet();
			// set bits in new BitSet
			for (int n = 0; n < 64; n++) {
				if (bits.charAt(k) == '1') {
					M.set(n, true);
				} else if (bits.charAt(k) == '0') {
					M.set(n, false);
				}
				k++;
			}
			M.xor(IV);
			// encrypt message
			result += messageEncrypt(M) + "\n";
		}

		if (used == 0) {
			String bits2 = "";
			M = new BitSet();
			for (int n = 0; n < 56; n++) {
				bits2 += "0";
			}
			bin = "8";
			bytes = bin.getBytes();
			str = Integer.toBinaryString(bytes[0]);
			if (str.length() > 4) {
				diff = (8 - str.length());
			}
			bits2 += (array[diff] + str);
			for (int n = 0; n < 64; n++) {
				if (bits2.charAt(n) == '1') {
					M.set(n, true);
				} else if (bits2.charAt(n) == '0') {
					M.set(n, false);
				}
			}
			M.xor(IV);
			result += messageEncrypt(M) + "\n";
		}
		return result;
	}

	/**
	 * messageEncrypt():
	 * 
	 * @param M
	 * 
	 *            Called by DES_encrypt() to handle all data conversion from
	 *            cleartext message to encrypted message
	 */
	public static String messageEncrypt(BitSet M) {
		BitSet IP = encryptIP(M);
		BitSet L = new BitSet(), R = new BitSet(), temp = new BitSet(), F = new BitSet();
		for (int i = 0; i < 32; i++) {
			L.set(i, IP.get(i));
		}
		for (int i = 0; i < 32; i++) {
			R.set(i, IP.get(i + 32));
		}
		// Generate R and L for 16 rounds
		for (int i = 0; i < 16; i++) {
			for (int j = 0; j < 32; j++) {
				temp.set(j, R.get(j));
			}
			F = calculateF(R, i);
			L.xor(F);
			for (int j = 0; j < 32; j++) {
				R.set(j, L.get(j));
			}
			for (int j = 0; j < 32; j++) {
				L.set(j, temp.get(j));
			}
		}

		BitSet RL = new BitSet(), newSet = new BitSet();
		for (int i = 0; i < 32; i++) {
			RL.set(i, R.get(i));
			RL.set(i + 32, L.get(i));
		}
		// permute newSet with SBoxes.FP
		for (int i = 0; i < 64; i++) {
			newSet.set(i, RL.get(SBoxes.FP[i] - 1));
		}
		// set IV to new encrypted block
		for (int i = 0; i < K_BITS; i++) {
			IV.set(i, newSet.get(i));
		}
		return hexConv(newSet, 64);
	}

	/**
	 * messageDecrypt():
	 * 
	 * @param M
	 * 
	 *            Called by DES_decrypt() to handle all data conversion for
	 *            message decryption
	 */
	public static String messageDecrypt(BitSet M) {
		BitSet IP = encryptIP(M);
		int iter = 15;
		BitSet L = new BitSet(), R = new BitSet(), temp = new BitSet(), F = new BitSet();
		for (int i = 0; i < 32; i++) {
			L.set(i, IP.get(i));
		}
		for (int i = 0; i < 32; i++) {
			R.set(i, IP.get(i + 32));
		}

		// Generate R and L for 16 rounds
		for (int i = 0; i < 16; i++) {
			for (int j = 0; j < 32; j++) {
				temp.set(j, R.get(j));
			}
			F = calculateF(R, iter);
			iter--;
			L.xor(F);
			for (int j = 0; j < 32; j++) {
				R.set(j, L.get(j));
			}
			for (int j = 0; j < 32; j++) {
				L.set(j, temp.get(j));
			}
		}

		BitSet RL = new BitSet(), newSet = new BitSet();
		for (int i = 0; i < 32; i++) {
			RL.set(i, R.get(i));
			RL.set(i + 32, L.get(i));
		}

		// permute newSet with SBoxes.FP
		for (int i = 0; i < 64; i++) {
			newSet.set(i, RL.get(SBoxes.FP[i] - 1));
		}
		newSet.xor(IV);
		// update Iv to be previous ciphertext
		for (int i = 0; i < K_BITS; i++) {
			IV.set(i, M.get(i));
		}
        
		String ret = BitSetToString(newSet, 64);
		String newString = removePadding(ret);
		if (newString.length() < 64) {
			FULL_BLOCK = false;
		}
		String ret2 = binaryToASCII(newString);
		return ret2;
	}
    
    /**
     * removePadding():
     *
     * @param str
     *
     *            Called by messageDecrypt(). removes the extra padding
     *            from current message after decrypting.
     * 
     */
	public static String removePadding(String str) {
		StringBuffer buff = new StringBuffer();
		// get the last value to remove number of bytes
		for (int i = 56; i < 64; i++) {
			buff.append(str.charAt(i));
		}
		String bin = binaryToASCII(buff.toString());
		Integer unused = 0;
		String newString = "";
		try {
			unused = Integer.parseInt(bin);
		} catch (Exception e) {
			FULL_BLOCK = true;
			// do not have an integert value (full block)!
			// e.printStackTrace();
		} finally {
			if (unused.equals(8)) {
			} else {
				for (int i = 0; i < (64 - (unused * 8)); i++) {
					newString += str.charAt(i);
				}
			}
		}
		return newString;
	}

	/**
	 * encryptIP():
	 * 
	 * @param M
	 * 
	 *            Called by messageEncrypt() and messageDecrypt() and uses IP
	 *            table from SBoxes for bit conversion
	 * 
	 */
	public static BitSet encryptIP(BitSet M) {
		BitSet IPSet = new BitSet();
		for (int i = 0; i < 64; i++) {
			IPSet.set(i, M.get(SBoxes.IP[i] - 1));
		}
		return IPSet;
	}

	/**
	 * calculateFD():
	 * 
	 * @param R, val
	 * 
	 *            Input 32 bit R BitSet and retrieve new 48 bit BitSet through
	 *            use of E, S and P tables.
	 */
	public static BitSet calculateF(BitSet R, int val) {
		BitSet key = new BitSet(), E = new BitSet(), S = new BitSet(), P = new BitSet(), B, var = new BitSet();
		for (int i = 0; i < 48; i++) {
			key.set(i, K[val].get(i));
		}
		// expand R with SBoxes.E
		for (int i = 0; i < 48; i++) {
			E.set(i, R.get(SBoxes.E[i] - 1));
		}
		E.xor(key);
		// calculate S with SBoxes.S
		// call calculateS() for each box B and set S accordingly

		for (int i = 0; i < 48; i += 6) {
			int c = i;
			for (int k = 0; k < 6; k++) {
				var.set(k, E.get(c));
				c++;
			}
			B = calculateS(var, i / 6);

			for (int j = 0; j < 4; j++) {
				S.set((j + (4 * (i / 6))), B.get(j));
			}
		}
		// permutate S with SBoxes.P
		for (int i = 0; i < 32; i++) {
			P.set(i, S.get(SBoxes.P[i] - 1));
		}
		return P;
	}

	/**
	 * calculateS():
	 * 
	 * @param B
	 *            , boxNum
	 * 
	 *            Use SBoxes.S to permute 6bit blocks into 4bit blocks
	 */
	public static BitSet calculateS(BitSet B, int boxNum) {
		String iStr = "", jStr = "", dec = "", bits = "";
		String[] array = { "", "0", "00", "000" };
		int i = 0, j = 0, d = 0, diff = 0;
		boolean bool;
		// calculate j (column)
		for (int n = 1; n < 5; n++) {
			bool = B.get(n);
			if (bool == true) {
				jStr += "1";
			} else {
				jStr += "0";
			}
		}
		// calculate i (row)
		if (B.get(0) == true) {
			iStr += "1";
		} else {
			iStr += "0";
		}
		if (B.get(5) == true) {
			iStr += "1";
		} else {
			iStr += "0";
		}
		i = Integer.parseInt(iStr, 2);
		j = Integer.parseInt(jStr, 2);
		// use SBoxes.S to permutate B. Requires i(row), j(column) and d
		// (S[#][d])
		d = ((16 * i) + j);

		int sVal = SBoxes.S[boxNum][d];
		dec = Integer.toString(sVal, 2);

		// formalize
		if (dec.length() < 4) {
			diff = (4 - dec.length());
			bits = (array[diff] + dec);
		} else {
			bits = dec;
		}

		BitSet SB = new BitSet();
		for (int n = 0; n < 4; n++) {
			if (bits.charAt(n) == '1') {
				SB.set(n, true);
			} else {
				SB.set(n, false);
			}
		}
		return SB;
	}

	/**
	 * genIV():
	 * 
	 * Utilizes SecureRandom to generate a unique IV for use in CBC mode
	 */
	public static void genIV() {
		SecureRandom rnd = new SecureRandom();
		IV = new BitSet();
		for (int i = 0; i < K_BITS; i++) {
			IV.set(i, rnd.nextBoolean());
		}
	}

	/**
	 * genDESkey:
	 * 
	 * Generates key and 16 sub keys. Checks for weak key based on sub key
	 * comparisons.
	 */
	static String genDESkey() {
		for (;;) {
			SecureRandom rnd = new SecureRandom();
			K_BITSET = new BitSet();
			for (int i = 0; i < K_BITS; i++) {
				K_BITSET.set(i, rnd.nextBoolean());
			}
			hex = hexConv(K_BITSET, K_BITS);
			// run key breakdown
			permute56bits();
			genKeys();
			KKeys();
			// check for weak key
			if (keyCheck()) {
				//System.out.println(hex);
				//hex = bitToDec(K_BITSET);
				return hex;
			}
			if (DEBUG) {
				System.out.println("K: ");
				printAsBinary(K_BITSET, 0);
				System.out.println();
			}
		}
	}
    
    
    /**
     * permute56bits:
     *
     *  permutes from PC-1 the 56-bits from the key K.
     *
     */
	static void permute56bits() {
		Kp_BITSET = new BitSet(Kp_BITS);
		for (int i = 0; i < Kp_BITS; i++) {
			Kp_BITSET.set(i, K_BITSET.get(SBoxes.PC1[i] - 1));
		}
		if (DEBUG) {
			System.out.println("K+: ");
			printAsBinary(Kp_BITSET, 0);
			System.out.println();
		}
	}
    
    /**
     * genKeys:
     *
     *  Generates the 16 subkeys.
     *
     */
	static void genKeys() {
		C = new BitSet[17];
		D = new BitSet[17];
		BitSet left = new BitSet();
		BitSet right = new BitSet();
		// set left & right bits
		for (int i = 0; i < 28; i++) {
			left.set(i, Kp_BITSET.get(i));
		}
		int index = 28;
		for (int k = 0; k < 28; k++) {
			right.set(k, Kp_BITSET.get(index + k));
		}
		BitSet c = left;
		C[0] = c;
		BitSet d = right;
		D[0] = d;
		for (int i = 0; i < 16; i++) {
			c = shiftLeft(c, SBoxes.rotations[i]);
			C[i + 1] = c;
			d = shiftLeft(d, SBoxes.rotations[i]);
			D[i + 1] = d;
		}

		if (DEBUG) {
			System.out.println();
			for (int i = 0; i < 17; i++) {
				System.out.print("C-" + (i) + ": ");
				printAsBinary(C[i], 28);
				System.out.print("D-" + (i) + ": ");
				printAsBinary(D[i], 28);
			}
		}
		KKeys();
	}
    
    /**
     * KKeys:
     *
     *  helper method for genKeys that fetches the indexes from the C and D
     *  arrays and permutes them from PC-2 block.
     */
	public static void KKeys() {
		BitSet gen = new BitSet();
		BitSet[] genArr = new BitSet[17];

		int fetchIndex = 0;
		for (int j = 1; j < 17; j++) {
			gen = C[j];
			for (int i = 28; i < 56; i++) {
				gen.set(i, D[j].get(fetchIndex));
				fetchIndex++;
			}
			genArr[j - 1] = gen;
			fetchIndex = 0;
		}

		if (DEBUG) {
			System.out.println();
			for (int i = 0; i < 16; i++) {
				printAsBinary(genArr[i], 56);
			}
			System.out.println();
		}

		for (int i = 0; i < 16; i++) {
			BitSet gen2 = new BitSet();
			for (int j = 0; j < 48; j++) {
				gen2.set(j, genArr[i].get(SBoxes.PC2[j] - 1));
			}
			K[i] = gen2;
		}

		if (DEBUG) {
			System.out.println();
			for (BitSet entry : K) {
				printAsBinary(entry, 48);
			}
		}
	}

	/**
	 * keyCheck():
	 * 
	 * If any sub keys are equal then the original key is weak key. Signals that
	 * key contains patterns or all of one value.
	 */
	public static boolean keyCheck() {
		for (int i = 0; i < 15; i++) {
			for (int j = 0; j < 16; j++) {
				BitSet temp = K[i].get(0, 64);
				temp.xor(K[j]);
				if (i != j && temp.isEmpty()) {
					return false;
				}
			}
		}
		return true;
	}

    /**
     * shiftLeft():
     *
     * @param left, numShift
     *      helper method to shift the bitset left by the number of shifts indicated
     *      by the second parameter
     */
	public static BitSet shiftLeft(BitSet left, int numShift) {
		BitSet c = new BitSet(28);
		c = left;
		boolean o;
		for (int i = 0; i < numShift; i++) {
			o = c.get(0);
			c = c.get(1, c.length());
			c.set(27, o);
			assert (o == c.get(c.length()));
		}
		return c;
	}

	/**
	 * hexConv():
	 * 
	 * @param BitSet
	 *            set, int size
	 * 
	 *            Converts BitSet to hexadecimal string
	 */
	public static String hexConv(BitSet set, int size) {
		String hex = "", s = "", full = "";
		for (int i = 0; i < size; i++) {
			if (set.get(i) == true) {
				hex += "1";
			} else {
				hex += "0";
			}
		}
		int j = 0;
		for (int i = 0; i < 16; i++) {
			s = hex.substring(j, j + 4);
			j += 4;
			full += Integer.toHexString(Integer.parseInt(s, 2));
		}
		return full;
	}
	
	public static String bitToDec(BitSet set){
		byte[] array = set.toByteArray();
		BigInteger big = new BigInteger(array);
		return big.toString();
	}

	/**
	 * binaryToASCII():
	 * 
	 * @param s
	 * 
	 *            Converts binary string to ascii
	 */
	static String binaryToASCII(String s) {
		String s2 = "";
		char nextChar;
		for (int i = 0; i <= s.length() - 8; i += 8) // this is a little tricky.
														// we want [0, 7], [9,
														// 16], etc
		{
			nextChar = (char) Integer.parseInt(s.substring(i, i + 8), 2);
			s2 += nextChar;
		}
		return s2;
	}

	/**
	 * printAsBinary():
	 * 
	 * @param bs
	 *            , size.
	 * 
	 *            Takes in a BitSet and prints the binary string version to std
	 *            out
	 */
	static void printAsBinary(BitSet bs, int size) {
		if (size == 0) {
			size = bs.size();
		}

		for (int i = 0; i < size; i++) {
			if (bs.get(i)) { // if true, 1
				System.out.print(1);
			} else { // else is 0
				System.out.print(0);
			}
		}
		System.out.println();
	}

	/**
	 * BitSetToString():
	 * 
	 * @param bs
	 *            , size.
	 * 
	 *            Takes in a BitSet and converts to a binary string
	 */
	static String BitSetToString(BitSet bs, int size) {
		StringBuffer buff = new StringBuffer();
		if (size == 0) {
			size = bs.size();
		}
		for (int i = 0; i < size; i++) {
			if (bs.get(i)) { // if true, 1
				buff.append("1");
			} else { // else is 0
				buff.append("0");
			}
		}
		return buff.toString();
	}

	/**
	 * hexToBinary():
	 * 
	 * @param hex
	 *            , size.
	 * 
	 *            Takes in a string in hex format and converts to a BitSet
	 */
	public static BitSet hexToBinary(String hex, int size) {
		BitSet set = new BitSet();
		BigInteger h = new BigInteger(hex, 16);
		String b = h.toString(2);
		if (b.length() < 64) {
			int diff = 64 - b.length();
			for (int i = 0; i < diff; i++) {
				b = "0" + b;
			}
		}
		for (int i = 0; i < b.length(); i++) {
			if (b.charAt(i) == '1') {
				set.set(i, true);
			} else {
				set.set(i, false);
			}
		}

		return set;
	}
}