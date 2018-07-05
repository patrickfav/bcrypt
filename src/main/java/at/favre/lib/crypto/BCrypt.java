package at.favre.lib.crypto;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public final class BCrypt {
    final static int SALT_LENGTH = 16;
    final static int MIN_COST = 4;
    final static int MAX_COST = 30;

    private final Charset defaultCharset = StandardCharsets.UTF_8;
    private final Version version;
    private final SecureRandom secureRandom;
    private final BCryptProtocol.Radix64Encoder encoder;

    public BCrypt(Version version, SecureRandom secureRandom, BCryptProtocol.Radix64Encoder encoder) {
        this.version = version;
        this.secureRandom = secureRandom;
        this.encoder = encoder;
    }

    public byte[] hash(int cost, char[] password) {
        return hash(cost, generateRandomSalt(), password);
    }

    public byte[] hash(int cost, byte[] salt, char[] password) {

        if (cost > MAX_COST || cost < MIN_COST) {
            throw new IllegalArgumentException("cost factor must be between " + MIN_COST + " and " + MAX_COST + ", was " + cost);
        }
        if (salt == null) {
            throw new IllegalArgumentException("salt must not be null");
        }
        if (salt.length != SALT_LENGTH) {
            throw new IllegalArgumentException("salt must be exactly " + SALT_LENGTH + " bytes, was " + salt.length);
        }
        if (password == null) {
            throw new IllegalArgumentException("provided password must not be null");
        }
        if (password.length > 72 || password.length < 1) {
            throw new IllegalArgumentException("password must be between 1 and 72 bytes encoded in utf-8, was " + password.length);
        }

        byte[] hash = new BCryptProtocol.BcryptHasher().cryptRaw(cost, salt, defaultCharset.encode(CharBuffer.wrap(password)).array());


        return createOutMessage(cost, salt, hash);
    }

    private byte[] generateRandomSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }

    private byte[] createOutMessage(int cost, byte[] salt, byte[] hash) {
        byte[] saltEncoded = encoder.encode(salt, salt.length);
        byte[] hashEncoded = encoder.encode(hash, hash.length);

        ByteBuffer byteBuffer = ByteBuffer.allocate(version.versionPrefix.length + 4 + 1 + saltEncoded.length + hashEncoded.length);
        byteBuffer.put(version.versionPrefix);
        byteBuffer.put(String.valueOf(cost).getBytes(defaultCharset));
        byteBuffer.put((byte) 0x24); //$
        byteBuffer.put(saltEncoded);
        byteBuffer.put(hashEncoded);
        return byteBuffer.array();
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
