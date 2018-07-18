package at.favre.lib.crypto.bcrypt;

/*
 * Copyright (c) 2012, 2013, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

import java.util.Arrays;

/**
 * Encoder for the custom Base64 variant of BCrypt (called Radix64 here). It has the same rules as Base64 but uses a
 * different mapping table than the various RFCs
 * <p>
 * According to Wikipedia:
 *
 * <blockquote>
 * Unix stores password hashes computed with crypt in the /etc/passwd file using radix-64 encoding called B64. It uses a
 * mostly-alphanumeric set of characters, plus . and /. Its 64-character set is "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".
 * Padding is not used.
 * </blockquote>
 */
public interface Radix64Encoder {


    /**
     * Encode given raw byte array to a Radix64 style, UTF-8 encoded byte array.
     *
     * @param rawBytes          to encode
     * @return UTF-8 encoded string representing radix64 encoded data
     */
    byte[] encode(byte[] rawBytes);

    /**
     * From a UTF-8 encoded string representing radix64 encoded data as byte array, decodes the raw bytes from it.
     *
     * @param utf8EncodedRadix64String from a string get it with <code>"m0CrhHm10qJ3lXRY.5zDGO".getBytes(StandardCharsets.UTF8)</code>
     * @return the raw bytes encoded by this utf-8 radix4 string
     */
    byte[] decode(byte[] utf8EncodedRadix64String);

    /**

     *
     * This class implements an encoder for encoding byte data using
     * the Base64 encoding scheme as used in OpenBSD which is not compatible
     * with the RFC Base64 schemas.
     *
     * Required Information for GPL-2 License
     *
     * Original: http://hg.openjdk.java.net/jdk8/jdk8/jdk/file/687fd7c7986d/src/share/classes/java/util/Base64.java
     *
     * Changes:
     *   - simplified alias method
     *   - simplified code
     *   - removed most features (padding, url encoding, MIME)
     *   - replaced with Base64 mapping table to use OpenBSD Radix64 table
     *
     */
    final class Default implements Radix64Encoder {

        /**
         * This array is a lookup table that translates 6-bit positive integer
         * index values into their "Base64 Alphabet" equivalents
         */
        private static final char[] toBase64 = {
                '.', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5',
                '6', '7', '8', '9'
        };

        private int outLength(int srclen) {
            int n = srclen % 3;
            return 4 * (srclen / 3) + (n == 0 ? 0 : n + 1);
        }

        /**
         * Encodes all bytes from the specified byte array into a newly-allocated
         * byte array using the encoding scheme. The returned byte
         * array is of the length of the resulting bytes.
         *
         * @param src the byte array to encode
         * @return A newly-allocated byte array containing the resulting
         * encoded bytes.
         */

        private int encode0(byte[] src, int end, byte[] dst) {
            char[] base64 = toBase64;
            int sp = 0;
            int slen = (end) / 3 * 3;
            int dp = 0;
            while (sp < slen) {
                int sl0 = Math.min(sp + slen, slen);
                for (int sp0 = sp, dp0 = dp; sp0 < sl0; ) {
                    int bits = (src[sp0++] & 0xff) << 16 |
                            (src[sp0++] & 0xff) << 8 |
                            (src[sp0++] & 0xff);
                    dst[dp0++] = (byte) base64[(bits >>> 18) & 0x3f];
                    dst[dp0++] = (byte) base64[(bits >>> 12) & 0x3f];
                    dst[dp0++] = (byte) base64[(bits >>> 6) & 0x3f];
                    dst[dp0++] = (byte) base64[bits & 0x3f];
                }
                int dlen = (sl0 - sp) / 3 * 4;
                dp += dlen;
                sp = sl0;
            }
            if (sp < end) {               // 1 or 2 leftover bytes
                int b0 = src[sp++] & 0xff;
                dst[dp++] = (byte) base64[b0 >> 2];
                if (sp == end) {
                    dst[dp++] = (byte) base64[(b0 << 4) & 0x3f];
                } else {
                    int b1 = src[sp++] & 0xff;
                    dst[dp++] = (byte) base64[(b0 << 4) & 0x3f | (b1 >> 4)];
                    dst[dp++] = (byte) base64[(b1 << 2) & 0x3f];
                }
            }
            return dp;
        }

        @Override
        public byte[] encode(byte[] rawBytes) {
            int len = outLength(rawBytes.length);          // dst array size
            byte[] dst = new byte[len];
            int ret = encode0(rawBytes, rawBytes.length, dst);
            if (ret != dst.length)
                return Arrays.copyOf(dst, ret);
            return dst;
        }

        /**
         * Lookup table for decoding unicode characters drawn from the
         * "Base64 Alphabet" into their 6-bit positive integer equivalents.
         * Characters that are not in the Base64 alphabet but fall within the bounds of
         * the array are encoded to -1.
         */
        private static final int[] fromBase64 = new int[256];

        static {
            Arrays.fill(fromBase64, -1);
            for (int i = 0; i < toBase64.length; i++)
                fromBase64[toBase64[i]] = i;
            fromBase64['='] = -2;
        }

        @Override
        public byte[] decode(byte[] src) {
            byte[] dst = new byte[outLengthDecode(src.length)];
            int ret = decode0(src, 0, src.length, dst);
            if (ret != dst.length) {
                dst = Arrays.copyOf(dst, ret);
            }
            return dst;
        }

        private int outLengthDecode(int len) {
            int paddings = 0;
            if (len == 0)
                return 0;
            if (len < 2) {
                throw new IllegalArgumentException("Input byte[] should at least have 2 bytes for radix64 bytes");
            }
            if ((len & 0x3) != 0)
                paddings = 4 - (len & 0x3);
            return 3 * ((len + 3) / 4) - paddings;
        }

        private int decode0(byte[] src, int sp, int sl, byte[] dst) {
            int dp = 0;
            int bits = 0;
            int shiftto = 18;       // pos of first byte of 4-byte atom
            while (sp < sl) {
                int b = src[sp++] & 0xff;
                if ((b = fromBase64[b]) < 0) {
                    if (b == -2) {
                        // padding byte '='
                        // =     shiftto==18 unnecessary padding
                        // x=    shiftto==12 a dangling single x
                        // x     to be handled together with non-padding case
                        // xx=   shiftto==6&&sp==sl missing last =
                        // xx=y  shiftto==6 last is not =
                        if (shiftto == 6 && (sp == sl || src[sp++] != '=') || shiftto == 18) {
                            throw new IllegalArgumentException("Input byte array has wrong 4-byte ending unit");
                        }
                        break;
                    }
                    throw new IllegalArgumentException("Illegal base64 character " + Integer.toString(src[sp - 1], 16));
                }
                bits |= (b << shiftto);
                shiftto -= 6;
                if (shiftto < 0) {
                    dst[dp++] = (byte) (bits >> 16);
                    dst[dp++] = (byte) (bits >> 8);
                    dst[dp++] = (byte) (bits);
                    shiftto = 18;
                    bits = 0;
                }
            }
            // reached end of byte array or hit padding '=' characters.
            if (shiftto == 6) {
                dst[dp++] = (byte) (bits >> 16);
            } else if (shiftto == 0) {
                dst[dp++] = (byte) (bits >> 16);
                dst[dp++] = (byte) (bits >> 8);
            } else if (shiftto == 12) {
                // dangling single "x", incorrectly encoded.
                throw new IllegalArgumentException("Last unit does not have enough valid bits");
            }

            if (sp < sl) {
                throw new IllegalArgumentException("Input byte array has incorrect ending byte at " + sp);
            }
            return dp;
        }
    }
}
