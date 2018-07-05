package at.favre.lib.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class BCrypt {

    private final Charset defaultCharset = StandardCharsets.UTF_8;
    private final Version version;

    public BCrypt(Version version) {
        this.version = version;
    }

    public byte[] hash(int cost, byte[] salt, char[] password) {
        return null;
    }

    private String createOutMessage(int cost, byte[] salt, byte[] hash) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(version.versionPrefix.length + salt.length + hash.length);
        byteBuffer.put(version.versionPrefix);
        byteBuffer.put(String.valueOf(cost).getBytes(defaultCharset));
        byteBuffer.put((byte) 0x24); //$
        byteBuffer.put(salt);
        byteBuffer.put(hash);
        return new String(byteBuffer.array(), defaultCharset);
    }


    public enum Version {
        /**
         * $2a$
         * <p>
         * The original specification did not define how to handle non-ASCII character, nor how to handle a null
         * terminator. The specification was revised to specify that when hashing strings:
         * - the string must be UTF-8 encoded
         * - the null terminator must be included
         */
        VERSION_2A(new byte[]{0x24, 0x32, 0x61, 0x24}),

        /**
         * $2b$ (2014/02)
         * <p>
         * A bug was discovered in the OpenBSD implementation of bcrypt. They were storing the length of their strings
         * in an unsigned char (i.e. 8-bit Byte). If a password was longer than 255 characters, it would overflow
         * and wrap at 255. To recognize possible incorrect hashes, a new version was created.
         */
        VERSION_2B(new byte[]{0x24, 0x32, 0x62, 0x24}),

        /**
         * $2x$ (2011)
         * <p>
         * Due to a bug in crypt_blowfish, a PHP implementation of BCrypt, a new version string was introduced to
         * recognize old hashes. It was mis-handling characters with the 8th bit set. Nobody else, including canonical
         * OpenBSD, adopted the idea of 2x/2y so this version marker change was limited to crypt_blowfish.
         */
        VERSION_2X(new byte[]{0x24, 0x32, 0x78, 0x24}),

        /**
         * $2y$ (2011)
         * <p>
         * See {@link #VERSION_2X}
         */
        VERSION_2Y(new byte[]{0x24, 0x32, 0x79, 0x24});

        public final byte[] versionPrefix;

        Version(byte[] versionPrefix) {
            this.versionPrefix = versionPrefix;
        }
    }
}
