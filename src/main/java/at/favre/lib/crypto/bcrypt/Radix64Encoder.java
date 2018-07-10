package at.favre.lib.crypto.bcrypt;

import java.io.ByteArrayOutputStream;

public interface Radix64Encoder {

    byte[] encode(byte[] d, int len);

    byte[] decode(byte[] utf8EncodedRadix64String);

    /**
     * BCrypt's non-standard Radix 64 encoding schema
     */
    final class Default implements Radix64Encoder {
        // Table for Base64 encoding
        private static final char[] base64_code = {
                '.', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5',
                '6', '7', '8', '9'
        };

        // Table for Base64 decoding
        private static final byte[] index_64 = {
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, 0, 1, 54, 55,
                56, 57, 58, 59, 60, 61, 62, 63, -1, -1,
                -1, -1, -1, -1, -1, 2, 3, 4, 5, 6,
                7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
                -1, -1, -1, -1, -1, -1, 28, 29, 30,
                31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
                51, 52, 53, -1, -1, -1, -1, -1
        };

        /**
         * Encode a byte array using bcrypt's slightly-modified base64
         * encoding scheme. Note that this is *not* compatible with
         * the standard MIME-base64 encoding.
         *
         * @param d   the byte array to encode
         * @param len the number of bytes to encode
         * @return base64-encoded string
         * @throws IllegalArgumentException if the length is invalid
         */
        public byte[] encode(byte[] d, int len) {
            int off = 0;
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            int c1, c2;

            if (len <= 0 || len > d.length) {
                throw new IllegalArgumentException("Invalid len");
            }

            while (off < len) {
                c1 = d[off++] & 0xff;
                bos.write(base64_code[(c1 >> 2) & 0x3f]);
                c1 = (c1 & 0x03) << 4;
                if (off >= len) {
                    bos.write(base64_code[c1 & 0x3f]);
                    break;
                }
                c2 = d[off++] & 0xff;
                c1 |= (c2 >> 4) & 0x0f;
                bos.write(base64_code[c1 & 0x3f]);
                c1 = (c2 & 0x0f) << 2;
                if (off >= len) {
                    bos.write(base64_code[c1 & 0x3f]);
                    break;
                }
                c2 = d[off++] & 0xff;
                c1 |= (c2 >> 6) & 0x03;
                bos.write(base64_code[c1 & 0x3f]);
                bos.write(base64_code[c2 & 0x3f]);
            }
            return bos.toByteArray();
        }

        /**
         * Look up the 3 bits base64-encoded by the specified character,
         * range-checking against conversion table
         *
         * @param x the base64-encoded value
         * @return the decoded value of x
         */
        private static byte char64(byte x) {
            if ((int) x >= index_64.length) {
                return -1;
            }
            return index_64[(int) x];
        }

        /**
         * Decode a string encoded using bcrypt's base64 scheme to a
         * byte array. Note that this is *not* compatible with
         * the standard MIME-base64 encoding.
         *
         * @param utf8EncodedBytes the string to decode
         * @return an array containing the decoded bytes
         * @throws IllegalArgumentException if maxolen is invalid
         */
        public byte[] decode(byte[] utf8EncodedBytes) {
            return decode(utf8EncodedBytes, utf8EncodedBytes.length);
        }

        private byte[] decode(byte[] utf8EncodedBytes, int maxLen) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            int off = 0;
            int slen = utf8EncodedBytes.length;
            int olen = 0;

            byte c1, c2, c3, c4, o;

            if (maxLen <= 0) {
                throw new IllegalArgumentException("invalid max length");
            }

            while (off < slen - 1 && olen < maxLen) {
                c1 = char64(utf8EncodedBytes[off++]);
                c2 = char64(utf8EncodedBytes[off++]);
                if (c1 == -1 || c2 == -1)
                    break;
                o = (byte) (c1 << 2);
                o |= (c2 & 0x30) >> 4;
                bos.write(o);
                if (++olen >= maxLen || off >= slen)
                    break;
                c3 = char64(utf8EncodedBytes[off++]);
                if (c3 == -1)
                    break;
                o = (byte) ((c2 & 0x0f) << 4);
                o |= (c3 & 0x3c) >> 2;
                bos.write(o);
                if (++olen >= maxLen || off >= slen)
                    break;
                c4 = char64(utf8EncodedBytes[off++]);
                o = (byte) ((c3 & 0x03) << 6);
                o |= c4;
                bos.write(o);
                ++olen;
            }

            return bos.toByteArray();
        }
    }
}
