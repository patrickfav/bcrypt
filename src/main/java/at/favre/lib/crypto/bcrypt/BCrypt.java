package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Objects;

public final class BCrypt {
    /**
     * Ascii hex pointer for '$'
     */
    static final byte SEPARATOR = 0x24;

    /**
     * Ascii hex pointer for '2'
     */
    static final byte MAJOR_VERSION = 0x32;
    static final int SALT_LENGTH = 16;
    static final int HASH_OUT_LENGTH = 23;
    static final int MAX_PW_LENGTH_BYTE = 71;
    static final int MIN_COST = 4;
    static final int MAX_COST = 30;

    public static BCrypt withDefaults() {
        return new BCrypt(Version.VERSION_2A, new SecureRandom(), new Radix64Encoder.Default());
    }

    public static BCrypt with(Version version) {
        return new BCrypt(version, new SecureRandom(), new Radix64Encoder.Default());
    }

    public static BCrypt with(SecureRandom secureRandom) {
        return new BCrypt(Version.VERSION_2A, secureRandom, new Radix64Encoder.Default());
    }

    public static BCrypt with(Version version, SecureRandom secureRandom) {
        return new BCrypt(version, secureRandom, new Radix64Encoder.Default());
    }

    private final Charset defaultCharset = StandardCharsets.UTF_8;
    private final Version version;
    private final SecureRandom secureRandom;
    private final Radix64Encoder encoder;
    private final LongPasswordStrategy longPasswordStrategy;

    private BCrypt(Version version, SecureRandom secureRandom, Radix64Encoder encoder) {
        this.version = version;
        this.secureRandom = secureRandom;
        this.encoder = encoder;
        this.longPasswordStrategy = new LongPasswordStrategy.StrictMaxPasswordLengthStrategy(MAX_PW_LENGTH_BYTE);
    }

    public byte[] hash(int cost, char[] password) {
        byte[] passwordBytes = null;
        try {
            passwordBytes = new String(CharBuffer.allocate(password.length + 1).put(password).array())
                    .getBytes(defaultCharset);
            return hash(cost, generateRandomSalt(), passwordBytes);
        } finally {
            if (passwordBytes != null) {
                Bytes.wrap(passwordBytes).mutable().secureWipe();
            }
        }
    }

    private byte[] generateRandomSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }

    byte[] hash(int cost, byte[] salt, byte[] password) {
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
        if (password.length > MAX_PW_LENGTH_BYTE) {
            password = longPasswordStrategy.derive(password);
        }

        byte[] pwWithNullTerminator = password = Bytes.wrap(password).append((byte) 0).array();
        try {
            byte[] hash = new BCryptOpenBSDProtocol().cryptRaw(1 << cost, salt, password);
            return createOutMessage(cost, salt, hash);
        } finally {
            Bytes.wrap(pwWithNullTerminator).mutable().secureWipe();
        }
    }

    private byte[] createOutMessage(int cost, byte[] salt, byte[] hash) {
        byte[] saltEncoded = encoder.encode(salt, salt.length);
        byte[] hashEncoded = encoder.encode(hash, HASH_OUT_LENGTH);
        byte[] costFactorBytes = String.format("%02d", cost).getBytes(defaultCharset);

        try {
            ByteBuffer byteBuffer = ByteBuffer.allocate(version.versionPrefix.length + costFactorBytes.length + 1 + saltEncoded.length + hashEncoded.length);
            byteBuffer.put(version.versionPrefix);
            byteBuffer.put(costFactorBytes);
            byteBuffer.put(SEPARATOR);
            byteBuffer.put(saltEncoded);
            byteBuffer.put(hashEncoded);
            return byteBuffer.array();
        } finally {
            Bytes.wrap(saltEncoded).mutable().secureWipe();
            Bytes.wrap(hashEncoded).mutable().secureWipe();
            Bytes.wrap(costFactorBytes).mutable().secureWipe();
        }
    }

    public Result verifyStrict(char[] password, char[] bcryptHash) {
        return verify(password, bcryptHash, true);
    }

    public Result verify(char[] password, char[] bcryptHash) {
        return verify(password, bcryptHash, false);
    }

    private Result verify(char[] password, char[] bcryptHash, boolean strictVersion) {
        byte[] passwordBytes = null;
        byte[] bcryptHashBytes = null;
        try {
            passwordBytes = new String(CharBuffer.allocate(password.length + 1).put(password).array()).getBytes(defaultCharset);
            bcryptHashBytes = new String(CharBuffer.allocate(bcryptHash.length + 1).put(bcryptHash).array()).getBytes(defaultCharset);
            return verify(passwordBytes, bcryptHashBytes, strictVersion);
        } finally {
            if (passwordBytes != null) {
                Bytes.wrap(passwordBytes).mutable().secureWipe();
            }
            if (bcryptHashBytes != null) {
                Bytes.wrap(bcryptHashBytes).mutable().secureWipe();
            }
        }
    }

    public Result verify(byte[] password, byte[] bcryptHash, boolean strictVersion) {
        Objects.requireNonNull(bcryptHash);

        BCryptParser parser = new BCryptParser.Default(defaultCharset, encoder);
        try {
            BCryptParser.Parts parts = parser.parse(bcryptHash);

            if (strictVersion && parts.version != version) {
                return new Result(parts, false);
            }

            byte[] refHash = BCrypt.with(parts.version).hash(parts.cost, parts.salt, password);
            return new Result(parts, Bytes.wrap(refHash).equals(bcryptHash));
        } catch (IllegalBCryptFormatException e) {
            return new Result(e);
        }
    }

    public static final class Result {
        public final BCryptParser.Parts details;
        public final boolean validFormat;
        public final boolean verified;
        public final String formatErrorMessage;

        public Result(IllegalBCryptFormatException e) {
            this(null, false, false, e.getMessage());
        }

        public Result(BCryptParser.Parts details, boolean verified) {
            this(details, true, verified, null);
        }

        private Result(BCryptParser.Parts details, boolean validFormat, boolean verified, String formatErrorMessage) {
            this.details = details;
            this.validFormat = validFormat;
            this.verified = verified;
            this.formatErrorMessage = formatErrorMessage;
        }
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
        VERSION_2A(new byte[]{SEPARATOR, MAJOR_VERSION, 0x61, SEPARATOR}),

        /**
         * $2b$ (2014/02)
         * <p>
         * A bug was discovered in the OpenBSD implementation of bcrypt. They were storing the length of their strings
         * in an unsigned char (i.e. 8-bit Byte). If a password was longer than 255 characters, it would overflow
         * and wrap at 255. To recognize possible incorrect hashes, a new version was created.
         */
        VERSION_2B(new byte[]{SEPARATOR, MAJOR_VERSION, 0x62, SEPARATOR}),

        /**
         * $2x$ (2011)
         * <p>
         * Due to a bug in crypt_blowfish, a PHP implementation of BCrypt, a new version string was introduced to
         * recognize old hashes. It was mis-handling characters with the 8th bit set. Nobody else, including canonical
         * OpenBSD, adopted the idea of 2x/2y so this version marker change was limited to crypt_blowfish.
         */
        VERSION_2X(new byte[]{SEPARATOR, MAJOR_VERSION, 0x78, SEPARATOR}),

        /**
         * $2y$ (2011)
         * <p>
         * See {@link #VERSION_2X}
         */
        VERSION_2Y(new byte[]{SEPARATOR, MAJOR_VERSION, 0x79, SEPARATOR});

        public final byte[] versionPrefix;

        Version(byte[] versionPrefix) {
            this.versionPrefix = versionPrefix;
        }

        public boolean test(byte[] data, boolean skipDollarTwo) {
            if (data.length >= versionPrefix.length) {
                for (int i = skipDollarTwo ? 2 : 0; i < versionPrefix.length; i++) {
                    if (data[i] != versionPrefix[i]) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }

        @Override
        public String toString() {
            return new String(versionPrefix, StandardCharsets.UTF_8);
        }
    }
}
