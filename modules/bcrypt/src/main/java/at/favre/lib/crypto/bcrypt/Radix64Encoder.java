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
     * A mod of the Apache Commons Codec Base64 logic
     */
    class Default implements Radix64Encoder {

        private static final int BITS_PER_ENCODED_BYTE = 6;
        private static final int BYTES_PER_UNENCODED_BLOCK = 3;
        private static final int BYTES_PER_ENCODED_BLOCK = 4;
        private static final int MASK_6BITS = 0x3f;
        private static final int MASK_8BITS = 0xff;
        private static final int DEFAULT_BUFFER_RESIZE_FACTOR = 2;
        private static final int DEFAULT_BUFFER_SIZE = 8192;

        /**
         * This array is a lookup table that translates 6-bit positive integer index values into their "Radix64ApacheCodec Alphabet"
         * equivalents.
         */
        private static final byte[] STANDARD_ENCODE_TABLE = {
                '.', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5',
                '6', '7', '8', '9'
        };

        /**
         * This array is a lookup table that translates Unicode characters drawn from the "Radix64ApacheCodec Alphabet" into their 6-bit positive i
         * integer equivalents.
         */
        private static final byte[] DECODE_TABLE = {
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 54, 55, 56, 57,
                58, 59, 60, 61, 62, 63, -1, -1, -1, -2, -1, -1, -1, 2, 3, 4, 5, 6, 7,
                8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                26, 27, -1, -1, -1, -1, -1, -1, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1
        };

        private final byte[] encodeTable;
        private final int decodeSize;
        private final int encodeSize;

        /**
         * Creates a Radix64ApacheCodec codec used for decoding (all modes) and encoding in URL-unsafe mode.
         * <p>
         * When encoding the line length and line separator are given in the constructor, and the encoding table is
         * STANDARD_ENCODE_TABLE.
         * </p>
         * <p>
         * Line lengths that aren't multiples of 4 will still essentially end up being multiples of 4 in the encoded data.
         * </p>
         * <p>
         * When decoding all variants are supported.
         * </p>
         *
         * @throws IllegalArgumentException The provided lineSeparator included some base64 characters. That's not going to work!
         * @since 1.4
         */
        public Default() {
            this.encodeSize = BYTES_PER_ENCODED_BLOCK;
            this.decodeSize = this.encodeSize - 1;
            this.encodeTable = STANDARD_ENCODE_TABLE;
        }

        @Override
        public byte[] encode(byte[] rawBytes) {
            final Context c = new Context();
            encode(rawBytes, 0, rawBytes.length, c);
            encode(rawBytes, 0, -1, c); // Notify encoder of EOF.
            final byte[] buf = new byte[c.pos - c.readPos];
            readResults(buf, 0, buf.length, c);
            return buf;
        }

        /**
         * Extracts buffered data into the provided byte[] array, starting at position bPos, up to a maximum of bAvail
         * bytes. Returns how many bytes were actually extracted.
         * <p>
         * Package protected for access from I/O streams.
         *
         * @param b       byte[] array to extract the buffered data into.
         * @param bPos    position in byte[] array to start extraction at.
         * @param bAvail  amount of bytes we're allowed to extract. We may extract fewer (if fewer are available).
         * @param context the context to be used
         */
        private void readResults(final byte[] b, final int bPos, final int bAvail, final Context context) {
            if (context.buffer != null) {
                final int len = Math.min(context.pos - context.readPos, bAvail);
                System.arraycopy(context.buffer, context.readPos, b, bPos, len);
                context.readPos += len;
                if (context.readPos >= context.pos) {
                    context.buffer = null; // so hasData() will return false, and this method can return -1
                }
            }
        }

        /**
         * <p>
         * Encodes all of the provided data, starting at inPos, for inAvail bytes. Must be called at least twice: once with
         * the data to encode, and once with inAvail set to "-1" to alert encoder that EOF has been reached, to flush last
         * remaining bytes (if not multiple of 3).
         * </p>
         * <p><b>Note: no padding is added when encoding using the URL-safe alphabet.</b></p>
         * <p>
         * Thanks to "commons" project in ws.apache.org for the bitwise operations, and general approach.
         * http://svn.apache.org/repos/asf/webservices/commons/trunk/modules/util/
         * </p>
         *
         * @param in      byte[] array of binary data to base64 encode.
         * @param inPos   Position to start reading data from.
         * @param inAvail Amount of bytes available from input for encoding.
         * @param context the context to be used
         */
        private void encode(final byte[] in, int inPos, final int inAvail, final Context context) {
            if (context.eof) {
                return;
            }
            // inAvail < 0 is how we're informed of EOF in the underlying data we're
            // encoding.
            if (inAvail < 0) {
                context.eof = true;
                if (0 == context.modulus) {
                    return; // no leftovers to process and not using chunking
                }
                final byte[] buffer = ensureBufferSize(encodeSize, context);
                final int savedPos = context.pos;
                switch (context.modulus) { // 0-2
                    case 0: // nothing to do here
                        break;
                    case 1: // 8 bits = 6 + 2
                        // top 6 bits:
                        buffer[context.pos++] = encodeTable[(context.ibitWorkArea >> 2) & MASK_6BITS];
                        // remaining 2:
                        buffer[context.pos++] = encodeTable[(context.ibitWorkArea << 4) & MASK_6BITS];
                        break;
                    case 2: // 16 bits = 6 + 6 + 4
                        buffer[context.pos++] = encodeTable[(context.ibitWorkArea >> 10) & MASK_6BITS];
                        buffer[context.pos++] = encodeTable[(context.ibitWorkArea >> 4) & MASK_6BITS];
                        buffer[context.pos++] = encodeTable[(context.ibitWorkArea << 2) & MASK_6BITS];
                        break;
                    default:
                        throw new IllegalStateException("Impossible modulus " + context.modulus);
                }
                context.currentLinePos += context.pos - savedPos; // keep track of current line position
            } else {
                for (int i = 0; i < inAvail; i++) {
                    final byte[] buffer = ensureBufferSize(encodeSize, context);
                    context.modulus = (context.modulus + 1) % BYTES_PER_UNENCODED_BLOCK;
                    int b = in[inPos++];
                    if (b < 0) {
                        b += 256;
                    }
                    context.ibitWorkArea = (context.ibitWorkArea << 8) + b; //  BITS_PER_BYTE
                    if (0 == context.modulus) { // 3 bytes = 24 bits = 4 * 6 bits to extract
                        buffer[context.pos++] = encodeTable[(context.ibitWorkArea >> 18) & MASK_6BITS];
                        buffer[context.pos++] = encodeTable[(context.ibitWorkArea >> 12) & MASK_6BITS];
                        buffer[context.pos++] = encodeTable[(context.ibitWorkArea >> 6) & MASK_6BITS];
                        buffer[context.pos++] = encodeTable[context.ibitWorkArea & MASK_6BITS];
                        context.currentLinePos += BYTES_PER_ENCODED_BLOCK;
                    }
                }
            }
        }

        /**
         * Ensure that the buffer has room for <code>size</code> bytes
         *
         * @param size    minimum spare space required
         * @param context the context to be used
         * @return the buffer
         */
        private byte[] ensureBufferSize(final int size, final Context context) {
            if ((context.buffer == null) || (context.buffer.length < context.pos + size)) {
                if (context.buffer == null) {
                    context.buffer = new byte[DEFAULT_BUFFER_SIZE];
                    context.pos = 0;
                    context.readPos = 0;
                } else {
                    final byte[] b = new byte[context.buffer.length * DEFAULT_BUFFER_RESIZE_FACTOR];
                    System.arraycopy(context.buffer, 0, b, 0, context.buffer.length);
                    context.buffer = b;
                }
                return context.buffer;
            }
            return context.buffer;
        }

        /**
         * <p>
         * Decodes all of the provided data, starting at inPos, for inAvail bytes. Should be called at least twice: once
         * with the data to decode, and once with inAvail set to "-1" to alert decoder that EOF has been reached. The "-1"
         * call is not necessary when decoding, but it doesn't hurt, either.
         * </p>
         * <p>
         * Ignores all non-base64 characters. This is how chunked (e.g. 76 character) data is handled, since CR and LF are
         * silently ignored, but has implications for other bytes, too. This method subscribes to the garbage-in,
         * garbage-out philosophy: it will not check the provided data for validity.
         * </p>
         * <p>
         * Thanks to "commons" project in ws.apache.org for the bitwise operations, and general approach.
         * http://svn.apache.org/repos/asf/webservices/commons/trunk/modules/util/
         * </p>
         *
         * @param in      byte[] array of ascii data to base64 decode.
         * @param inPos   Position to start reading data from.
         * @param inAvail Amount of bytes available from input for encoding.
         * @param context the context to be used
         */
        private void decode(final byte[] in, int inPos, final int inAvail, final Context context) {
            if (context.eof) {
                return;
            }
            if (inAvail < 0) {
                context.eof = true;
            }
            for (int i = 0; i < inAvail; i++) {
                final byte[] buffer = ensureBufferSize(decodeSize, context);
                final byte b = in[inPos++];
                if (b >= 0) {
                    final int result = DECODE_TABLE[b];
                    if (result >= 0) {
                        context.modulus = (context.modulus + 1) % BYTES_PER_ENCODED_BLOCK;
                        context.ibitWorkArea = (context.ibitWorkArea << BITS_PER_ENCODED_BYTE) + result;
                        if (context.modulus == 0) {
                            buffer[context.pos++] = (byte) ((context.ibitWorkArea >> 16) & MASK_8BITS);
                            buffer[context.pos++] = (byte) ((context.ibitWorkArea >> 8) & MASK_8BITS);
                            buffer[context.pos++] = (byte) (context.ibitWorkArea & MASK_8BITS);
                        }
                    }
                }
            }

            // Two forms of EOF as far as base64 decoder is concerned: actual
            // EOF (-1) and first time '=' character is encountered in stream.
            // This approach makes the '=' padding characters completely optional.
            if (context.eof && context.modulus != 0) {
                final byte[] buffer = ensureBufferSize(decodeSize, context);

                // We have some spare bits remaining
                // Output all whole multiples of 8 bits and ignore the rest
                switch (context.modulus) {
                    // case 0 : // impossible, as excluded above
                    case 1: // 6 bits - ignore entirely
                        // TODO not currently tested; perhaps it is impossible?
                        break;
                    case 2: // 12 bits = 8 + 4
                        context.ibitWorkArea = context.ibitWorkArea >> 4; // dump the extra 4 bits
                        buffer[context.pos++] = (byte) ((context.ibitWorkArea) & MASK_8BITS);
                        break;
                    case 3: // 18 bits = 8 + 8 + 2
                        context.ibitWorkArea = context.ibitWorkArea >> 2; // dump 2 bits
                        buffer[context.pos++] = (byte) ((context.ibitWorkArea >> 8) & MASK_8BITS);
                        buffer[context.pos++] = (byte) ((context.ibitWorkArea) & MASK_8BITS);
                        break;
                    default:
                        throw new IllegalStateException("Impossible modulus " + context.modulus);
                }
            }
        }

        @Override
        public byte[] decode(byte[] utf8EncodedRadix64String) {
            final Context c = new Context();
            decode(utf8EncodedRadix64String, 0, utf8EncodedRadix64String.length, c);
            decode(utf8EncodedRadix64String, 0, -1, c); // Notify decoder of EOF.
            final byte[] result = new byte[c.pos];
            readResults(result, 0, result.length, c);
            return result;
        }

        /**
         * Holds thread context so classes can be thread-safe.
         * <p>
         * This class is not itself thread-safe; each thread must allocate its own copy.
         *
         * @since 1.7
         */
        static class Context {

            /**
             * Place holder for the bytes we're dealing with for our based logic.
             * Bitwise operations store and extract the encoding or decoding from this variable.
             */
            int ibitWorkArea;

            /**
             * Buffer for streaming.
             */
            byte[] buffer;

            /**
             * Position where next character should be written in the buffer.
             */
            int pos;

            /**
             * Position where next character should be read from the buffer.
             */
            int readPos;

            /**
             * Boolean flag to indicate the EOF has been reached. Once EOF has been reached, this object becomes useless,
             * and must be thrown away.
             */
            boolean eof;

            /**
             * Variable tracks how many characters have been written to the current line. Only used when encoding. We use
             * it to make sure each encoded line never goes beyond lineLength (if lineLength &gt; 0).
             */
            int currentLinePos;

            /**
             * Writes to the buffer only occur after every 3/5 reads when encoding, and every 4/8 reads when decoding. This
             * variable helps track that.
             */
            int modulus;

            Context() {
            }
        }
    }
}
