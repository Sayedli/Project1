import java.util.Arrays;
import java.math.BigInteger;

/**
 *
 * Tiny SHA-3 implementation derived from NIST publication
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
 * inspired by https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 *
 *  Project 1 TCSS 487 With Palo Barreto
 *
 * @author Arsh Singh
 * @author Hassan Ali
 */

public class KMACXOF256 {

    // Keccak round constants
    private static final long[] keccakfRndc = { 0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L,
            0x8000000000008009L, 0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L,
            0x000000008000000aL, 0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL,
            0x800000008000000aL, 0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L,
            0x8000000080008008L };

    // Keccak pi lane permutation
    private static final int[] keccakfPilane = { 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
            14, 22, 9, 6, 1 };

    // Keccak rotation offsets
    private static final int[] keccakfRotc = { 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18,
            39, 61, 20, 44 };

    /**
     * Perform Keccak permutation on the input state.
     *
     * @param stateIn  Input state
     * @param bitLen   Bit length
     * @param rounds   Number of rounds
     * @return         Permuted state
     */
    private static long[] keccak(long[] stateIn, int bitLen, int rounds) {
        long[] stateOut = stateIn;
        int l = floorLog(bitLen / 25);
        for (int i = 12 + 2 * l - rounds; i < 12 + 2 * l; i++) {
            stateOut = iota(chi(rhoPhi(theta(stateOut))), i);
        }
        return stateOut;
    }

    /**
     * Theta step of the Keccak permutation.
     *
     * @param stateIn  Input state
     * @return         State after theta step
     */
    private static long[] theta(long[] stateIn) {
        long[] stateOut = new long[25];
        long[] C = new long[5];

        for (int i = 0; i < 5; i++) {
            C[i] = stateIn[i] ^ stateIn[i + 5] ^ stateIn[i + 10] ^ stateIn[i + 15] ^ stateIn[i + 20];
        }

        for (int i = 0; i < 5; i++) {
            long d = C[(i + 4) % 5] ^ rotateLane64(C[(i + 1) % 5], 1);

            for (int j = 0; j < 5; j++) {
                stateOut[i + 5 * j] = stateIn[i + 5 * j] ^ d;
            }
        }

        return stateOut;
    }

    /**
     * Rho and Pi steps of the Keccak permutation.
     *
     * @param stateIn  Input state
     * @return         State after rho and pi steps
     */
    private static long[] rhoPhi(long[] stateIn) {
        long[] stateOut = new long[25];
        stateOut[0] = stateIn[0];
        long t = stateIn[1], temp;
        int ind;
        for (int i = 0; i < 24; i++) {
            ind = keccakfPilane[i];
            temp = stateIn[ind];
            stateOut[ind] = rotateLane64(t, keccakfRotc[i]);
            t = temp;
        }
        return stateOut;
    }

    /**
     * Chi step of the Keccak permutation.
     *
     * @param stateIn  Input state
     * @return         State after chi step
     */
    private static long[] chi(long[] stateIn) {
        long[] stateOut = new long[25];
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                long tmp = ~stateIn[(i + 1) % 5 + 5 * j] & stateIn[(i + 2) % 5 + 5 * j];
                stateOut[i + 5 * j] = stateIn[i + 5 * j] ^ tmp;
            }
        }
        return stateOut;
    }

    /**
     * Iota step of the Keccak permutation.
     *
     * @param stateIn  Input state
     * @param round    Current round index
     * @return         State after iota step
     */
    private static long[] iota(long[] stateIn, int round) {
        stateIn[0] ^= keccakfRndc[round];
        return stateIn;
    }

    /**
     * Sponge function to generate pseudorandom output.
     *
     * @param in       Input byte array
     * @param bitLen   Bit length
     * @param cap      Capacity
     * @return         Pseudorandom output
     */
    private static byte[] sponge(byte[] in, int bitLen, int cap) {
        int rate = 1600 - cap;
        byte[] padded = in.length % (rate / 8) == 0 ? in : padTenOne(rate, in);
        long[][] states = byteArrayToStates(padded, cap);
        long[] stcml = new long[25];
        for (long[] st : states) {
            stcml = keccak(xorStates(stcml, st), 1600, 24);
        }

        long[] out = {};
        int offset = 0;
        do {
            out = Arrays.copyOf(out, offset + rate / 64);
            System.arraycopy(stcml, 0, out, offset, rate / 64);
            offset += rate / 64;
            stcml = keccak(stcml, 1600, 24);
        } while (out.length * 64 < bitLen);

        return stateToByteArray(out, bitLen);
    }

    /**
     * Pad the input with 10*1 padding.
     *
     * @param rate  Rate
     * @param in    Input byte array
     * @return      Padded byte array
     */
    private static byte[] padTenOne(int rate, byte[] in) {
        int bytesToPad = (rate / 8) - in.length % (rate / 8);
        byte[] padded = new byte[in.length + bytesToPad];
        for (int i = 0; i < in.length + bytesToPad; i++) {
            if (i < in.length) padded[i] = in[i];
            else if (i == in.length + bytesToPad - 1) padded[i] = (byte) 0x80;
            else padded[i] = 0;
        }

        return padded;
    }

    /**
     * Compute SHAKE256 hash.
     *
     * @param in      Input byte array
     * @param bitLen  Bit length
     * @return        SHAKE256 hash
     */
    public static byte[] SHAKE256(byte[] in, int bitLen) {
        byte[] uin = Arrays.copyOf(in, in.length + 1);
        int bytesToPad = 136 - in.length % (136);
        uin[in.length] = bytesToPad == 1 ? (byte) 0x9f : 0x1f;
        return sponge(uin, bitLen, 512);
    }

    /**
     * Compute cSHAKE256 hash with custom parameters.
     *
     * @param in            Input byte array
     * @param bitLength     Bit length
     * @param functionName  Function name
     * @param customStr     Custom string
     * @return              cSHAKE256 hash
     */
    public static byte[] cSHAKE256(byte[] in, int bitLength, byte[] functionName, byte[] customStr) {
        if (functionName.length == 0 && customStr.length == 0) return SHAKE256(in, bitLength);

        byte[] fin = concat(encodeString(functionName), encodeString(customStr));
        fin = concat(bytePad(fin, 136), in);
        fin = concat(fin, new byte[]{0x04});

        return sponge(fin, bitLength, 512);
    }

    /**
     * Compute KMACXOF256 hash with custom parameters and key.
     *
     * @param key           Key byte array
     * @param in            Input byte array
     * @param bitLength     Bit length
     * @param customString  Custom string
     * @return              KMACXOF256 hash
     */
    public static byte[] KMACXOF256(byte[] key, byte[] in, int bitLength, byte[] customString) {
        byte[] newX = concat(concat(bytePad(encodeString(key), 136), in), rightEncode(BigInteger.ZERO));
        return cSHAKE256(newX, bitLength, "KMAC".getBytes(), customString);
    }

    /**
     * Encode BigInteger using right encoding.
     *
     * @param x  BigInteger to encode
     * @return   Encoded byte array
     */
    private static byte[] rightEncode(BigInteger x) {
        assert 0 < x.compareTo(new BigInteger(String.valueOf(Math.pow(2, 2040))));

        int n = 1;

        while (x.compareTo(new BigInteger(String.valueOf((int) Math.pow(2, (8 * n))))) != -1) {
            n++;
        }

        byte[] xBytes = x.toByteArray();

        if ((xBytes[0] == 0) && (xBytes.length > 1)) {
            byte[] temp = new byte[xBytes.length - 1];
            System.arraycopy(xBytes, 1, temp, 0, xBytes.length - 1);
            xBytes = temp;
        }

        byte[] output = new byte[xBytes.length + 1];

        for (int i = 0; i < xBytes.length; i++) {
            output[xBytes.length - (i + 1)] = xBytes[i];
        }

        output[0] = (byte) n;
        return output;
    }

    /**
     * Encode BigInteger using left encoding.
     *
     * @param x  BigInteger to encode
     * @return   Encoded byte array
     */
    private static byte[] leftEncode(BigInteger x) {
        assert 0 < x.compareTo(new BigInteger(String.valueOf(Math.pow(2, 2040))));

        int n = 1;

        while (x.compareTo(new BigInteger(String.valueOf((int) Math.pow(2, (8 * n))))) != -1) {
            n++;
        }

        byte[] xBytes = x.toByteArray();

        if ((xBytes[0] == 0) && (xBytes.length > 1)) {
            byte[] temp = new byte[xBytes.length - 1];
            System.arraycopy(xBytes, 1, temp, 0, xBytes.length - 1);
            xBytes = temp;
        }

        byte[] output = new byte[xBytes.length + 1];
        for (int i = 0; i < xBytes.length; i++) {
            output[xBytes.length - (i)] = xBytes[i];
        }

        output[0] = (byte) n;
        return output;
    }

    /**
     * Encode string as byte array with length prefix.
     *
     * @param S  Input string
     * @return   Encoded byte array
     */
    private static byte[] encodeString(byte[] S) {
        if (S == null || S.length == 0) {
            return leftEncode(BigInteger.ZERO);
        } else {
            return concat(leftEncode(new BigInteger(String.valueOf(S.length << 3))), S);
        }
    }

    /**
     * Pad byte array to desired length.
     *
     * @param X  Input byte array
     * @param w  Desired length
     * @return   Padded byte array
     */
    private static byte[] bytePad(byte[] X, int w) {
        assert w > 0;

        byte[] wEnc = leftEncode(BigInteger.valueOf(w));

        byte[] z = new byte[w * ((wEnc.length + X.length + w - 1) / w)];
        System.arraycopy(wEnc, 0, z, 0, wEnc.length);
        System.arraycopy(X, 0, z, wEnc.length, X.length);

        for (int i = wEnc.length + X.length; i < z.length; i++) {
            z[i] = (byte) 0;
        }

        return z;
    }

    /**
     * Rotate 64-bit lane left or right.
     *
     * @param x  Input 64-bit lane
     * @param y  Rotation offset
     * @return   Rotated lane
     */
    private static long rotateLane64(long x, int y) {
        return (x << (y % 64)) | (x >>> (64 - (y % 64)));
    }


    /**
     * Compute floor logarithm of a number.
     *
     * @param n  Input number
     * @return   Floor logarithm
     */
    private static int floorLog(int n) {
        if (n < 0) throw new IllegalArgumentException("Undefined log for negative numbers.");
        int exp = -1;
        while (n > 0) {
            n = n >>> 1;
            exp++;
        }
        return exp;
    }

    /**
     * XOR two Keccak states.
     *
     * @param s1  First state
     * @param s2  Second state
     * @return    XOR result
     */
    private static long[] xorStates(long[] s1, long[] s2) {
        long[] out = new long[25];
        for (int i = 0; i < s1.length; i++) {
            out[i] = s1[i] ^ s2[i];
        }
        return out;
    }

    /**
     * Convert Keccak state to byte array.
     *
     * @param state   Keccak state
     * @param bitLen  Bit length
     * @return        Byte array
     */
    private static byte[] stateToByteArray(long[] state, int bitLen) {
        if (state.length * 64 < bitLen)
            throw new IllegalArgumentException("Insufficient state length, cannot produce desired bit length.");
        byte[] out = new byte[bitLen / 8];
        int wrdInd = 0;
        while (wrdInd * 64 < bitLen) {
            long word = state[wrdInd++];
            int fill = wrdInd * 64 > bitLen ? (bitLen - (wrdInd - 1) * 64) / 8 : 8;
            for (int b = 0; b < fill; b++) {
                byte ubt = (byte) (word >>> (8 * b) & 0xFF);
                out[(wrdInd - 1) * 8 + b] = ubt;
            }
        }

        return out;
    }

    /**
     * Convert byte array to Keccak states.
     *
     * @param in   Input byte array
     * @param cap  Capacity
     * @return     Keccak states
     */
    private static long[][] byteArrayToStates(byte[] in, int cap) {
        long[][] states = new long[(in.length * 8) / (1600 - cap)][25];
        int offset = 0;
        for (int i = 0; i < states.length; i++) {
            long[] state = new long[25];
            for (int j = 0; j < (1600 - cap) / 64; j++) {
                long word = bytesToWord(offset, in);
                state[j] = word;
                offset += 8;
            }

            states[i] = state;
        }
        return states;
    }

    /**
     * Convert byte array to 64-bit word.
     *
     * @param offset  Starting offset
     * @param in      Input byte array
     * @return        64-bit word
     */
    private static long bytesToWord(int offset, byte[] in) {
        if (in.length < offset + 8) throw new IllegalArgumentException("Index out of range, Byte range unreachable.");

        long word = 0L;
        for (int i = 0; i < 8; i++) {
            word += (((long) in[offset + i]) & 0xff) << (8 * i);
        }
        return word;
    }


    /**
     * XOR two byte arrays.
     *
     * @param b1  First byte array
     * @param b2  Second byte array
     * @return    XOR result
     */
    public static byte[] xorBytes(byte[] b1, byte[] b2) {
        byte[] out = new byte[b1.length];
        for (int i = 0; i < b1.length; i++) {
            out[i] = (byte) (b1[i] ^ b2[i]);
        }
        return out;
    }


    /**
     * Concatenate two byte arrays.
     *
     * @param b1  First byte array
     * @param b2  Second byte array
     * @return    Concatenated byte array
     */
    public static byte[] concat(byte[] b1, byte[] b2) {
        byte[] z = new byte[b1.length + b2.length];
        System.arraycopy(b1, 0, z, 0, b1.length);
        System.arraycopy(b2, 0, z, b1.length, b2.length);
        return z;
    }

    /**
     * Convert byte array to hexadecimal string.
     *
     * @param bytes  Input byte array
     * @return       Hexadecimal string
     */
    public static String bytesToHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(Byte.toUnsignedInt(b));
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * Convert hexadecimal string to byte array.
     *
     * @param s  Input string
     * @return   Byte array
     */
    public static byte[] hexStringToBytes(String s) {
        s = s.replaceAll("\\s", "");
        byte[] val = new byte[s.length() / 2];
        for (int i = 0; i < val.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(s.substring(index, index + 2), 16);
            val[i] = (byte) j;
        }
        return val;
    }
}