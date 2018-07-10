package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Objects;

public final class BCrypt {
    private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    /**
     * Fixed lenght of the bcrypt salt
     */
    public static final int SALT_LENGTH = 16;
    /**
     * The max length of the password in bytes excluding lats null-terminator byte
     */
    public static final int MAX_PW_LENGTH_BYTE = 71;

    /**
     * Minimum allowed cost factor
     */
    public static final int MIN_COST = 4;

    /**
     * Maximum allowed cost factor
     */
    public static final int MAX_COST = 30;

    /**
     * Ascii hex pointer for '2'
     */
    static final byte MAJOR_VERSION = 0x32;

    /**
     * The raw hash out length in byte
     */
    static final int HASH_OUT_LENGTH = 23;
    /**
     * Ascii hex pointer for '$'
     */
    static final byte SEPARATOR = 0x24;

    private BCrypt() {
    }

    /**
     * Create a new instance of bcrypt hash with default version {@link Version#VERSION_2A}.
     * Will throw an exception if given password is longer than the max length support for bycrpt of {@link #MAX_PW_LENGTH_BYTE}.
     *
     * @return new bcrypt hash instance
     */
    public static Hasher withDefaults() {
        return new Hasher(Version.VERSION_2A, new SecureRandom(), new LongPasswordStrategy.StrictMaxPasswordLengthStrategy(MAX_PW_LENGTH_BYTE));
    }

    /**
     * Create a new instance of bcrypt hash with given {@link Version}.
     * Will throw an exception if given password is longer than the max length support for bycrpt of {@link #MAX_PW_LENGTH_BYTE}.
     *
     * @param version defines what version of bcrypt will be generated (mostly the version identifier changes)
     * @return new bcrypt hash instance
     */
    public static Hasher with(Version version) {
        return new Hasher(version, new SecureRandom(), new LongPasswordStrategy.StrictMaxPasswordLengthStrategy(MAX_PW_LENGTH_BYTE));
    }

    /**
     * Create a new instance of bcrypt hash with default version {@link Version#VERSION_2A}.
     * The passed {@link SecureRandom} is used for generating the random salt.
     * Will throw an exception if given password is longer than the max length support for bycrpt of {@link #MAX_PW_LENGTH_BYTE}.
     *
     * @param secureRandom to use for random salt generation
     * @return new bcrypt hash instance
     */
    public static Hasher with(SecureRandom secureRandom) {
        return new Hasher(Version.VERSION_2A, secureRandom, new LongPasswordStrategy.StrictMaxPasswordLengthStrategy(MAX_PW_LENGTH_BYTE));
    }

    /**
     * Create a new instance of bcrypt hash with default version {@link Version#VERSION_2A}.
     * The passed {@link LongPasswordStrategy} will decide what to do when the password is longer than the supported
     * {@link #MAX_PW_LENGTH_BYTE}
     *
     * @param longPasswordStrategy decides what to do on pw that are too long
     * @return new bcrypt hash instance
     */
    public static Hasher with(LongPasswordStrategy longPasswordStrategy) {
        return new Hasher(Version.VERSION_2A, new SecureRandom(), longPasswordStrategy);
    }

    /**
     * Create a new instance with custom version, secureRandom and long password strategy
     *
     * @param version              defines what version of bcrypt will be generated (mostly the version identifier changes)
     * @param secureRandom         to use for random salt generation
     * @param longPasswordStrategy decides what to do on pw that are too long
     * @return new bcrypt hash instance
     */
    public static Hasher with(Version version, SecureRandom secureRandom, LongPasswordStrategy longPasswordStrategy) {
        return new Hasher(version, secureRandom, longPasswordStrategy);
    }

    /**
     * Creates a new instance of bcrypt verifier to verify a password against a given hash
     *
     * @return new verifier instance
     */
    public static Verifyer verifyer() {
        return new Verifyer();
    }

    /**
     * Can create bcrypt hashes
     */
    public static final class Hasher {
        private final Charset defaultCharset = DEFAULT_CHARSET;
        private final Version version;
        private final SecureRandom secureRandom;
        private final Radix64Encoder encoder;
        private final LongPasswordStrategy longPasswordStrategy;

        private Hasher(Version version, SecureRandom secureRandom, LongPasswordStrategy longPasswordStrategy) {
            this.version = version;
            this.secureRandom = secureRandom;
            this.encoder = new Radix64Encoder.Default();
            this.longPasswordStrategy = longPasswordStrategy;
        }

        /**
         * Hashes given password with the OpenBSD bcrypt schema. The cost factor will define how expensive the hash will
         * be to generate. This method will use a {@link SecureRandom} to generate the internal 16 byte hash.
         *
         * @param cost     exponential cost factor between {@link #MIN_COST} and {@link #MAX_COST} e.g. 12 --&gt; 2^12 = 4,096 iterations
         * @param password to hash, will be internally converted to a utf-8 byte array representation
         * @return bcrypt hash as a char array utf-8 encoded which includes version, cost-factor, salt and the raw hash (as radix64)
         */
        public char[] hashToChar(int cost, char[] password) {
            return defaultCharset.decode(ByteBuffer.wrap(hash(cost, password))).array();
        }

        /**
         * Hashes given password with the OpenBSD bcrypt schema. The cost factor will define how expensive the hash will
         * be to generate. This method will use a {@link SecureRandom} to generate the internal 16 byte hash.
         *
         * @param cost     exponential cost factor between {@link #MIN_COST} and {@link #MAX_COST} e.g. 12 --&gt; 2^12 = 4,096 iterations
         * @param password to hash, will be internally converted to a utf-8 byte array representation
         * @return bcrypt hash utf-8 encoded byte array which includes version, cost-factor, salt and the raw hash (as radix64)
         */
        public byte[] hash(int cost, char[] password) {
            if (password == null) {
                throw new IllegalArgumentException("provided password must not be null");
            }

            byte[] passwordBytes = null;
            try {
                passwordBytes = new String(CharBuffer.wrap(password).array()).getBytes(defaultCharset);
                return hash(cost, Bytes.random(SALT_LENGTH, secureRandom).array(), passwordBytes);
            } finally {
                if (passwordBytes != null) {
                    Bytes.wrap(passwordBytes).mutable().secureWipe();
                }
            }
        }

        /**
         * Hashes given password with the OpenBSD bcrypt schema. The cost factor will define how expensive the hash will
         * be to generate. This method will use given salt byte array
         *
         * @param cost     exponential cost factor between {@link #MIN_COST} and {@link #MAX_COST} e.g. 12 --&gt; 2^12 = 4,096 iterations
         * @param salt     a random 16 byte long word, only used once
         * @param password the utf-8 encoded byte array representation
         * @return bcrypt hash utf-8 encoded byte array which includes version, cost-factor, salt and the raw hash (as radix64)
         */
        public byte[] hash(int cost, byte[] salt, byte[] password) {
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
                ByteBuffer byteBuffer = ByteBuffer.allocate(version.versionPrefix.length +
                        costFactorBytes.length + 1 + saltEncoded.length + hashEncoded.length);
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
    }

    /**
     * Can verify bcrypt hashes
     */
    public static final class Verifyer {
        private final Charset defaultCharset = DEFAULT_CHARSET;
        private final Radix64Encoder encoder;

        private Verifyer() {
            this.encoder = new Radix64Encoder.Default();
        }

        /**
         * Verify given bcrypt hash, which includes salt and cost factor with given raw password requiring a specific
         * version. If the version does not match, {@link Result#verified} will be false, even if the hash matches.
         * <p>
         * If given hash has an invalid format {@link Result#validFormat} will be false; see also
         * {@link Result#formatErrorMessage} for easier debugging.
         *
         * @param password        to compare against the hash
         * @param bcryptHash      to compare against the password
         * @param expectedVersion will check for this version and wil not verify if versions do not match
         * @return result object, see {@link Result} for more info
         */
        public Result verifyStrict(byte[] password, byte[] bcryptHash, Version expectedVersion) {
            return verify(password, bcryptHash, expectedVersion);
        }

        /**
         * Verify given bcrypt hash, which includes salt and cost factor with given raw password.
         * The result will have {@link Result#verified} true if they match. If given hash has an
         * invalid format {@link Result#validFormat} will be false; see also {@link Result#formatErrorMessage}
         * for easier debugging.
         *
         * @param password   to compare against the hash
         * @param bcryptHash to compare against the password
         * @return result object, see {@link Result} for more info
         */
        public Result verify(byte[] password, byte[] bcryptHash) {
            return verify(password, bcryptHash, null);
        }

        /**
         * Verify given bcrypt hash, which includes salt and cost factor with given raw password requiring a specific
         * version. If the version does not match, {@link Result#verified} will be false, even if the hash matches.
         * <p>
         * If given hash has an invalid format {@link Result#validFormat} will be false; see also
         * {@link Result#formatErrorMessage} for easier debugging.
         *
         * @param password        to compare against the hash
         * @param bcryptHash      to compare against the password
         * @param expectedVersion will check for this version and wil not verify if versions do not match
         * @return result object, see {@link Result} for more info
         */
        public Result verifyStrict(char[] password, char[] bcryptHash, Version expectedVersion) {
            return verify(password, bcryptHash, expectedVersion);
        }

        /**
         * Verify given bcrypt hash, which includes salt and cost factor with given raw password.
         * The result will have {@link Result#verified} true if they match. If given hash has an
         * invalid format {@link Result#validFormat} will be false; see also {@link Result#formatErrorMessage}
         * for easier debugging.
         *
         * @param password   to compare against the hash
         * @param bcryptHash to compare against the password
         * @return result object, see {@link Result} for more info
         */
        public Result verify(char[] password, char[] bcryptHash) {
            return verify(password, bcryptHash, null);
        }

        private Result verify(char[] password, char[] bcryptHash, Version requiredVersion) {
            byte[] passwordBytes = null;
            byte[] bcryptHashBytes = null;
            try {
                passwordBytes = new String(CharBuffer.wrap(password).array()).getBytes(defaultCharset);
                bcryptHashBytes = new String(CharBuffer.wrap(bcryptHash).array()).getBytes(defaultCharset);
                return verify(passwordBytes, bcryptHashBytes, requiredVersion);
            } finally {
                if (passwordBytes != null) {
                    Bytes.wrap(passwordBytes).mutable().secureWipe();
                }
                if (bcryptHashBytes != null) {
                    Bytes.wrap(bcryptHashBytes).mutable().secureWipe();
                }
            }
        }

        /**
         * Verify given password against a bcryptHash
         */
        private Result verify(byte[] password, byte[] bcryptHash, Version requiredVersion) {
            Objects.requireNonNull(bcryptHash);

            BCryptParser parser = new BCryptParser.Default(defaultCharset, encoder);
            try {
                BCryptParser.Parts parts = parser.parse(bcryptHash);

                if (requiredVersion != null && parts.version != requiredVersion) {
                    return new Result(parts, false);
                }

                byte[] refHash = BCrypt.with(parts.version).hash(parts.cost, parts.salt, password);
                return new Result(parts, MessageDigest.isEqual(refHash, bcryptHash));
            } catch (IllegalBCryptFormatException e) {
                return new Result(e);
            }
        }
    }

    /**
     * Result of a bcrypt hash verification
     */
    public static final class Result {
        /**
         * The parts of the modular crypt format (salt, raw hash, cost factor, version)
         */
        public final BCryptParser.Parts details;

        /**
         * If the given format was valid. E.g. '$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u'
         */
        public final boolean validFormat;

        /**
         * If the given password matches the hash
         */
        public final boolean verified;

        /**
         * Optional error message if {@link #validFormat} is false
         */
        public final String formatErrorMessage;

        Result(IllegalBCryptFormatException e) {
            this(null, false, false, e.getMessage());
        }

        Result(BCryptParser.Parts details, boolean verified) {
            this(details, true, verified, null);
        }

        private Result(BCryptParser.Parts details, boolean validFormat, boolean verified, String formatErrorMessage) {
            this.details = details;
            this.validFormat = validFormat;
            this.verified = verified;
            this.formatErrorMessage = formatErrorMessage;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Result result = (Result) o;
            return validFormat == result.validFormat &&
                    verified == result.verified &&
                    Objects.equals(details, result.details) &&
                    Objects.equals(formatErrorMessage, result.formatErrorMessage);
        }

        @Override
        public int hashCode() {
            return Objects.hash(details, validFormat, verified, formatErrorMessage);
        }

        @Override
        public String toString() {
            return "Result{" +
                    "details=" + details +
                    ", validFormat=" + validFormat +
                    ", verified=" + verified +
                    ", formatErrorMessage='" + formatErrorMessage + '\'' +
                    '}';
        }
    }

    /**
     * The supported version identifiers for bcrypt according to the modular crypt format.
     * <p>
     * See: https://passlib.readthedocs.io/en/stable/modular_crypt_format.html
     */
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
         * <p>
         * Nobody else, including canonical OpenBSD, adopted the idea of 2x/2y. This version marker change was limited
         * to crypt_blowfish.
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
