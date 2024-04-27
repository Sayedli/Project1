/**
 * @Authors: Ali & Singh
 * Implementation of the SHA-3 cryptographic hash function.
 *
 */
public class Sha3 {
    // Constants
    public static final long BYTE_MASK = 0xFF;
    public static int KECCAKF_ROUNDS = 24;

    // Bitwise rotation operation for 64-bit integers
    static long ROTL64(long x, long y) {
        var u = (((x) << (y)) | ((x) >>> (64 - (y))));
        if (64 - y < 0) {
            throw new RuntimeException("y out of valid range for uint");
        }
        return u;
    }

    // Print hexadecimal representation of byte array
    public static void phex(byte[] Xs) {
        for (var x : Xs) System.out.printf("%02X ", x);
        System.out.println();
    }

    // Initialize SHAKE128 context
    static sha3_ctx_t shake128_init(sha3_ctx_t c) {
        sha3_init(c, 16);
        return c;
    }

    // Initialize SHAKE256 context
    static sha3_ctx_t shake256_init(sha3_ctx_t c) {
        sha3_init(c, 32);
        return c;
    }

    // Perform Keccak-f permutation
    static void sha3_keccakf(sha3_ctx_t c) {
        long[] st = c.byWord(); // Retrieve the state array
        // Keccak round constants
        long[] keccakf_rndc = { /* values */ };
        // Rotation offsets
        var keccakf_rotc = new int[]{ /* values */ };
        // Permutation indices
        var keccakf_piln = new int[]{ /* values */ };

        int j, r;
        long t;
        var bc = new long[5];

        for (r = 0; r < KECCAKF_ROUNDS; r++) {
            // Theta step
            for (int i = 0; i < 5; i++) {
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            }

            // Rho and Pi steps
            for (int i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5] ^ Long.rotateLeft(bc[(i + 1) % 5], 1);
                for (j = 0; j < 25; j += 5) {
                    st[j + i] ^= t;
                }
            }

            // Chi step
            for (j = 0; j < 25; j += 5) {
                System.arraycopy(st, j, bc, 0, 5);
                for (int i = 0; i < 5; i++) {
                    st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
            }
            st[0] ^= keccakf_rndc[r];
        }

        // Reverse byte order
        for (int i = 0; i < 25; i++) {
            st[i] = Long.reverseBytes(st[i]);
        }
        c.setWord(st);
    }

    // Initialize SHA-3 context
    static void sha3_init(sha3_ctx_t c, int mdlen) {
        c.setWord(new long[25]);
        c.mdlen = mdlen;
        c.rsiz = 200 - 2 * mdlen;
        c.pt = 0;
    }

    // Update SHA-3 context with input data
    static void sha3_update(sha3_ctx_t c, byte[] data, long len) {
        int j = c.pt;
        for (int i = 0; i < len; i++) {
            c.b[j++] ^= data[i];
            if (j >= c.rsiz) {
                sha3_keccakf(c);
                j = 0;
            }
        }
        c.pt = j;
    }

    // Finalize SHA-3 computation and output the hash
    static void sha3_final(byte[] md, sha3_ctx_t c) throws IllegalArgumentException {
        if (md == null) {
            throw new IllegalArgumentException("sha3_final: md is null");
        }

        c.b[c.pt] ^= 0x06;
        c.b[c.rsiz - 1] ^= 0x80;
        sha3_keccakf(c);

        if (c.mdlen >= 0) System.arraycopy(c.b, 0, md, 0, c.mdlen);
    }

    // Compute SHA-3 hash
    public static void sha3(byte[] in, long inlen, byte[] md, int mdlen) {
        sha3_ctx_t sha3ctx = new sha3_ctx_t();
        sha3_init(sha3ctx, mdlen);
        sha3_update(sha3ctx, in, inlen);
        sha3_final(md, sha3ctx);
    }

    // Update SHAKE context with input data
    static void shake_update(sha3_ctx_t c, byte[] data, long len) {
        sha3_update(c, data, len);
    }

    // Squeeze output from SHAKE context
    static void shake_out(sha3_ctx_t c, byte[] out, long len) {
        int j = c.pt;
        for (int i = 0; i < len; i++) {
            if (j >= c.rsiz) {
                sha3_keccakf(c);
                j = 0;
            }
            out[i] = c.b[j++];
        }
        c.pt = j;
    }

    // SHA-3 context structure
    static class sha3_ctx_t {
        public byte[] b;
        public int pt, rsiz, mdlen;

        sha3_ctx_t() {
            this.b = new byte[200];
        }

        public long[] byWord() {
            long[] words = new long[b.length / 8];
            for (int i = 0; i < 25; i++) {
                var v = new long[8];
                for (int j = 0; j < 8; j++) {
                    v[j] = this.b[i * 8 + j] & 0xFFL;
                }

                words[i] = v[7] |
                        (v[6] << 8) |
                        (v[5] << 16) |
                        (v[4] << 24) |
                        (v[3] << 32) |
                        (v[2] << 40) |
                        (v[1] << 48) |
                        (v[0] << 56);
            }
            return words;
        }

        public void setWord(long[] words) {
            for (int w = 0; w < words.length; w++) {
                long word = words[w];
                for (int i = 0; i < 8; i++) {
                    b[w * 8 + i] = (byte) (((word >>> (7 - i) * 8)) & 0xFF);
                }
            }
        }

        public void setBytes(byte[] bytes) {
            if (this.b.length < bytes.length) {
                this.b = new byte[bytes.length];
            }
            System.arraycopy(bytes, 0, this.b, 0, bytes.length);
        }
    }
}
