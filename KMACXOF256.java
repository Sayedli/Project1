import java.security.SecureRandom;
import java.util.Arrays;
import java.math.BigInteger;

public class KMACXOF256 {

    // XOR operation between two byte arrays
    public static byte[] xor(byte[] X, byte[] Y) {
        for (int i = 0; i < Math.min(X.length, Y.length); i++) X[i] ^= Y[i];
        return X;
    }

    // Left encoding of a long integer
    public static byte[] left_encode(long x) {
        int n = 0;
        if (x == 0) return new byte[]{1, 0};
        long y = x;
        while (y != 0) {
            n++;
            y >>>= 8;
        }
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[n - i - 1] = (byte) (x & 0xFF);
            x >>>= 8;
        }
        return appendBytes(new byte[]{(byte) n}, b);
    }

    // Left encoding of a BigInteger
    public static byte[] left_encode(BigInteger x) {
        byte[] b = x.toByteArray();
        return appendBytes(new byte[]{(byte) b.length}, b);
    }

    // Left encoding of a byte array
    public static byte[] left_encode(byte[] b) {
        return appendBytes(new byte[]{(byte) b.length}, b);
    }

    // Append multiple byte arrays into a single byte array
    public static byte[] appendBytes(byte[]... Xs) {
        int newlen = 0;
        for (byte[] x : Xs) newlen += (x != null) ? x.length : 0;

        byte[] newXs = new byte[newlen];
        int ptr = 0;
        for (byte[] x : Xs) {
            if (x == null) continue;
            System.arraycopy(x, 0, newXs, ptr, x.length);
            ptr += x.length;
        }
        return newXs;
    }

    // Encode a byte array as a string
    static public byte[] encode_string(byte[] S) {
        return appendBytes(left_encode(S.length * 8L), S);
    }

    // Encode a BigInteger as a string
    static public byte[] encode_string(BigInteger S) {
        return encode_string(S.toByteArray());
    }

    // Right encoding of an integer
    private static byte[] right_encode(int i) {
        return new byte[]{(byte) 0, (byte) 1};
    }

    // Generate random bytes
    private static byte[] randomBytes() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[512 / 8];
        random.nextBytes(bytes);
        return bytes;
    }

    // Symmetric encryption using KMACXOF256
    public static byte[] symmetricEncrypt(byte[] m, byte[] pw) {
        byte[] z = randomBytes();
        byte[] ke_ka = KMACXOF256(
                appendBytes(z, pw),
                "".getBytes(),
                1024,
                "S".getBytes());
        byte[] ke = Arrays.copyOfRange(ke_ka, 0, 64);
        byte[] ka = Arrays.copyOfRange(ke_ka, 64, 128);
        byte[] c = KMACXOF256(ke, "".getBytes(), m.length * 8, "SKE".getBytes());
        xor(c, m);
        byte[] t = KMACXOF256(ka, m, 512, "SKA".getBytes());
        byte[] symmetricCryptogram = appendBytes(z, c, t);
        return symmetricCryptogram;
    }

    // Symmetric decryption using KMACXOF256
    public static byte[] symmetricDecrypt(byte[] zct, byte[] pw) {
        byte[] z = Arrays.copyOfRange(zct, 0, 64);
        byte[] c = Arrays.copyOfRange(zct, 64, zct.length - 64);
        byte[] t = Arrays.copyOfRange(zct, zct.length - 64, zct.length);
        byte[] ke_ka = KMACXOF256(appendBytes(z, pw), "".getBytes(), 1024, "S".getBytes());
        byte[] ke = Arrays.copyOfRange(ke_ka, 0, 64);
        byte[] ka = Arrays.copyOfRange(ke_ka, 64, 128);
        byte[] m = xor(KMACXOF256(ke, "".getBytes(), c.length * 8, "SKE".getBytes()), c);
        byte[] tPrime = KMACXOF256(ka, m, 512, "SKA".getBytes());
        if (Arrays.equals(tPrime, t)) {
            return m;
        } else {
            throw new IllegalArgumentException("Decryption failed: authentication tag does not match");
        }
    }

    // Perform cSHAKE256 operation
    public static byte[] cSHAKE256(byte[] X, int L, byte[] N, byte[] S) {
        Sha3.sha3_ctx_t ctx = new Sha3.sha3_ctx_t();
        Sha3.sha3_init(ctx, L);
        byte[] bytepad_data = bytepad(appendBytes(encode_string(N), encode_string(S)), 136);
        absorb(ctx, appendBytes(bytepad_data, X));
        return squeeze(ctx, L / 8);
    }

    // Absorb data into SHA-3 context
    public static void absorb(Sha3.sha3_ctx_t ctx, byte[] X) {
        while (X.length > 136) {
            byte[] d = Arrays.copyOfRange(X, 0, 136);
            xor(ctx.b, d);
            Sha3.sha3_keccakf(ctx);
            X = Arrays.copyOfRange(X, 136, X.length);
        }
        byte[] lastBlock = new byte[200];
        xor(lastBlock, X);
        lastBlock[X.length] ^= 0x04;
        lastBlock[135] ^= 0x80;
        xor(ctx.b, lastBlock);
        Sha3.sha3_keccakf(ctx);
    }

    // Squeeze data from SHA-3 context
    static byte[] squeeze(Sha3.sha3_ctx_t ctx, int output_length) {
        int rate = 136;
        int c = 1600 / 8 - rate;

        byte[] out = new byte[output_length];
        int ptr = 0;
        while (ptr < output_length) {
            if ((output_length - ptr) >= rate) {
                System.arraycopy(ctx.b, 0, out, ptr, rate);
                ptr += rate;
            } else {
                System.arraycopy(ctx.b, 0, out, ptr, output_length % rate);
                ptr += output_length % rate;
            }
            Sha3.sha3_keccakf(ctx);
        }
        return out;
    }

    // Compute KMACXOF256
    public static byte[] KMACXOF256(byte[] K, byte[] X, int L, byte[] S) {
        byte[] newX = appendBytes(bytepad(encode_string(K), 136), X, right_encode(0));
        return cSHAKE256(newX, L, "KMAC".getBytes(), S);
    }

    // Byte pad data
    public static byte[] bytepad(byte[] X, int w) {
        assert w > 0;
        byte[] encodedW = left_encode(w);
        byte[] z = new byte[w * ((encodedW.length + X.length + w - 1) / w)];
        System.arraycopy(encodedW, 0, z, 0, encodedW.length);
        System.arraycopy(X, 0, z, encodedW.length, X.length);
        for (int i = encodedW.length + X.length; i < z.length; i++) {
            z[i] = (byte) 0;
        }
        return z;
    }
}
