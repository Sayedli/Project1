/**
 * @Authors: Ali & Singh
 * Implementation of the SHA-3 cryptographic hash function.
 */
public class Sha3 {

    static class sha3_ctx_t {
        byte[] b;
        int pt;
        int c;
        int rsiz;

        sha3_ctx_t() {
            this.b = new byte[200];
        }

        public long[] byWord() {
            long[] words = new long[b.length / 8];
            for (int i = 0; i < words.length; i++) {
                words[i] = (b[i * 8] & 0xFFL) << 56
                        | (b[i * 8 + 1] & 0xFFL) << 48
                        | (b[i * 8 + 2] & 0xFFL) << 40
                        | (b[i * 8 + 3] & 0xFFL) << 32
                        | (b[i * 8 + 4] & 0xFFL) << 24
                        | (b[i * 8 + 5] & 0xFFL) << 16
                        | (b[i * 8 + 6] & 0xFFL) << 8
                        | (b[i * 8 + 7] & 0xFFL);
            }
            return words;
        }

        public void setWord(long[] words) {
            for (int i = 0; i < words.length; i++) {
                b[i * 8] = (byte) (words[i] >>> 56);
                b[i * 8 + 1] = (byte) (words[i] >>> 48);
                b[i * 8 + 2] = (byte) (words[i] >>> 40);
                b[i * 8 + 3] = (byte) (words[i] >>> 32);
                b[i * 8 + 4] = (byte) (words[i] >>> 24);
                b[i * 8 + 5] = (byte) (words[i] >>> 16);
                b[i * 8 + 6] = (byte) (words[i] >>> 8);
                b[i * 8 + 7] = (byte) words[i];
            }
        }
    }

    // Constants
    public static final long BYTE_MASK = 0xFF;
    public static int KECCAKF_ROUNDS = 24;

    static long[] keccakf_rndc = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL,
            0x8000000080008000L, 0x000000000000808BL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008AL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
            0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800AL, 0x800000008000000AL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    static int[] keccakf_rotc = {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55,
            2, 14, 27, 41, 56, 8, 25, 43, 62, 18,
            39, 61, 20, 44
    };

    static int[] keccakf_piln = {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21,
            24, 4, 15, 23, 19, 13, 12, 2, 20, 14,
            22, 9, 6, 1
    };

    // Bitwise rotation operation for 64-bit integers
    static long ROTL64(long x, int y) {
        return (x << y) | (x >>> (64 - y));
    }

    // Print hexadecimal representation of byte array
    public static void phex(byte[] Xs) {
        for (var x : Xs) System.out.printf("%02X ", x);
        System.out.println();
    }

    // Initialize SHAKE128 context
    static sha3_ctx_t shake128_init() {
        sha3_ctx_t c = new sha3_ctx_t();
        sha3_init(c, 200 - 256);
        return c;
    }

    // Initialize SHAKE256 context
    static sha3_ctx_t shake256_init() {
        sha3_ctx_t c = new sha3_ctx_t();
        sha3_init(c, 200 - 512);
        return c;
    }

    // Perform Keccak-f permutation
    static void sha3_keccakf(sha3_ctx_t c) {
        long[] st = c.byWord(); // Retrieve the state array

        long t;
        long[] bc = new long[5];

        for (int r = 0; r < KECCAKF_ROUNDS; r++) {
            // Theta step
            for (int i = 0; i < 5; i++) {
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            }

            for (int i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5) {
                    st[j + i] ^= t;
                }
            }

            // Rho and Pi steps
            t = st[1];
            for (int i = 0; i < 24; i++) {
                int j = keccakf_piln[i];
                bc[0] = st[j];
                st[j] = ROTL64(t, keccakf_rotc[i]);
                t = bc[0];
            }

            // Chi step
            for (int j = 0; j < 25; j += 5) {
                System.arraycopy(st, j, bc, 0, 5);
                for (int i = 0; i < 5; i++) {
                    st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
            }

            // Iota step
            st[0] ^= keccakf_rndc[r];
        }

        c.setWord(st);
    }

    // Initialize SHA-3 context
    static void sha3_init(sha3_ctx_t c, int rate) {
        c.b = new byte[200];
        c.c = 1600 - rate * 8;
        c.rsiz = 200 - c.c / 8;
        c.pt = 0;
    }

    // Update SHA-3 context with input data
    static void sha3_update(sha3_ctx_t c, byte[] data, int len) {
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
    static void sha3_final(byte[] md, sha3_ctx_t c) {
        if (md == null) {
            throw new IllegalArgumentException("sha3_final: md is null");
        }

        c.b[c.pt] ^= 0x06;
        c.b[c.rsiz - 1] ^= 0x80;
        sha3_keccakf(c);

        System.arraycopy(c.b, 0, md, 0, md.length);
    }

    // Compute SHA-3 hash
    public static void sha3(byte[] in, int inlen, byte[] md, int mdlen) {
        sha3_ctx_t sha3ctx = new sha3_ctx_t();
        sha3_init(sha3ctx, 200 - (mdlen * 2));
        sha3_update(sha3ctx, in, inlen);
        sha3_final(md, sha3ctx);
    }


    // Update SHAKE context with input data
    static void shake_update(sha3_ctx_t c, byte[] data, int len) {
        sha3_update(c, data, len);
    }

    // Squeeze output from SHAKE context
    static void shake_out(sha3_ctx_t c, byte[] out, int len) {
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
}