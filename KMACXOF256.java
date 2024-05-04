import java.security.SecureRandom;
import java.util.Arrays;

public class KMACXOF256 {

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

    // Right encoding of an integer
    private static byte[] right_encode(int L) {
        int n = 0;
        long x = L;
        byte[] result = new byte[9];
        while (x != 0) {
            n++;
            result[n] = (byte)(x & 0xFF);
            x >>= 8;
        }
        result[0] = (byte) n;
        return Arrays.copyOfRange(result, 0, n + 1);
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

    // Generate random bytes
    private static byte[] randomBytes() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[512 / 8];
        random.nextBytes(bytes);
        return bytes;
    }

    // Perform cSHAKE256 operation
    public static byte[] cSHAKE256(byte[] X, int L, byte[] N, byte[] S) {
        int rate = 136; // SHA-3 256-bit capacity
        Sha3.sha3_ctx_t ctx = new Sha3.sha3_ctx_t();
        Sha3.sha3_init(ctx, rate);

        byte[] bytepad_data = bytepad(appendBytes(encode_string(N), encode_string(S)), rate);
        absorb(ctx, bytepad_data);
        absorb(ctx, X);
        return squeeze(ctx, L / 8);
    }

    // Absorb data into SHA-3 context
    public static void absorb(Sha3.sha3_ctx_t ctx, byte[] X) {
        int rate = (1600 - ctx.rsiz) / 8;
        int i = 0;
        while (i + rate <= X.length) {
            for (int j = 0; j < rate; j++) {
                ctx.b[j] ^= X[i + j];
            }
            Sha3.sha3_keccakf(ctx);
            i += rate;
        }
        for (int j = 0; j < X.length - i; j++) {
            ctx.b[j] ^= X[i + j];
        }
        ctx.b[X.length - i] ^= 0x04;
        ctx.b[rate - 1] ^= 0x80;
    }

    // Squeeze data from SHA-3 context
    static byte[] squeeze(Sha3.sha3_ctx_t ctx, int output_length) {
        int rate = 136; // SHA-3 256-bit capacity

        byte[] out = new byte[output_length];
        int ptr = 0;
        while (ptr < output_length) {
            int len = Math.min(rate, output_length - ptr);
            System.arraycopy(ctx.b, 0, out, ptr, len);
            ptr += len;
            if (ptr < output_length) {
                Sha3.sha3_keccakf(ctx);
            }
        }
        return out;
    }

    // Compute KMACXOF256
    public static byte[] KMACXOF256(byte[] K, byte[] X, int L, byte[] S) {
        byte[] newX = appendBytes(bytepad(encode_string(K), 136), X, right_encode(L));
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
