package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.bytes.BytesTransformer;
import at.favre.lib.bytes.BytesValidators;
import at.favre.lib.bytes.MutableBytes;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * The main access point the Bcrypt APIs
 */
@SuppressWarnings("WeakerAccess")
public final class BCrypt {
    private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    /**
     * Fixed length of the bcrypt salt
     */
    public static final int SALT_LENGTH = 16;

    /**
     * Minimum allowed cost factor
     */
    public static final int MIN_COST = 4;

    /**
     * Maximum allowed cost factor
     */
    public static final int MAX_COST = 31;

     /**
     * The raw hash out length in byte
     */
    public static final int HASH_OUT_LENGTH = 23;
    
    /**
     * Ascii hex pointer for '2'
     */
    static final byte MAJOR_VERSION = 0x32;

    /**
     * Ascii hex pointer for '$'
     */
    static final byte SEPARATOR = 0x24;

    private BCrypt() {
    }

    /**
     * Create a new instance of bcrypt hash with default version {@link Version#VERSION_2A}.
     * Will throw an exception if given password is longer than the max length support for bcrypt of {@link Version#allowedMaxPwLength}.
     *
     * @return new bcrypt hash instance
     */
    public static Hasher withDefaults() {
        return new Hasher(Version.VERSION_2A, new SecureRandom(), LongPasswordStrategies.strict(Version.VERSION_2A));
    }

    /**
     * Create a new instance of bcrypt hash with given {@link Version}.
     * Will throw an exception if given password is longer than the max length support for bcrypt of {@link Version#allowedMaxPwLength}.
     *
     * @param version defines what version of bcrypt will be generated (mostly the version identifier changes)
     * @return new bcrypt hash instance
     */
    public static Hasher with(Version version) {
        return new Hasher(version, new SecureRandom(), LongPasswordStrategies.strict(version));
    }

    /**
     * Create a new instance of bcrypt hash with default version {@link Version#VERSION_2A}.
     * The passed {@link SecureRandom} is used for generating the random salt.
     * Will throw an exception if given password is longer than the max length support for bcrypt of {@link Version#allowedMaxPwLength}.
     *
     * @param secureRandom to use for random salt generation
     * @return new bcrypt hash instance
     */
    public static Hasher with(SecureRandom secureRandom) {
        return new Hasher(Version.VERSION_2A, secureRandom, LongPasswordStrategies.strict(Version.VERSION_2A));
    }

    /**
     * Create a new instance of bcrypt hash with default version {@link Version#VERSION_2A}.
     * The passed {@link LongPasswordStrategy} will decide what to do when the password is longer than the supported
     * {@link Version#allowedMaxPwLength}
     *
     * @param longPasswordStrategy decides what to do on pw that are too long
     * @return new bcrypt hash instance
     */
    public static Hasher with(LongPasswordStrategy longPasswordStrategy) {
        return new Hasher(Version.VERSION_2A, new SecureRandom(), longPasswordStrategy);
    }

    /**
     * Create a new instance with custom version and long password strategy
     *
     * @param version              defines what version of bcrypt will be generated (mostly the version identifier changes)
     * @param longPasswordStrategy decides what to do on pw that are too long
     * @return new bcrypt hash instance
     */
    public static Hasher with(Version version, LongPasswordStrategy longPasswordStrategy) {
        return new Hasher(version, new SecureRandom(), longPasswordStrategy);
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
     * Creates a new instance of bcrypt verifier to verify a password against a given hash.
     *
     * @return new verifier instance
     */
    public static Verifyer verifyer() {
        return verifyer(null, null);
    }

    /**
     * Creates a new instance of bcrypt verifier to verify a password against a given hash.
     *
     * @param version to use, also matters in  {@link Verifyer#verifyStrict(byte[], byte[])}
     * @return new verifier instance
     */
    public static Verifyer verifyer(Version version) {
        return new Verifyer(version, LongPasswordStrategies.strict(version));
    }

    /**
     * Creates a new instance of bcrypt verifier to verify a password against a given hash.
     * This "verify" also respects the passed {@link LongPasswordStrategy} for creating the reference hash - use this
     * if you use one while hashing.
     *
     * @param version              to use, also matters in  {@link Verifyer#verifyStrict(byte[], byte[])}
     * @param longPasswordStrategy used to create the reference hash.
     * @return new verifier instance
     */
    public static Verifyer verifyer(Version version, LongPasswordStrategy longPasswordStrategy) {
        return new Verifyer(version, longPasswordStrategy);
    }

    /**
     * Can create bcrypt hashes
     */
    public static final class Hasher {
        private final Charset defaultCharset = DEFAULT_CHARSET;
        private final Version version;
        private final SecureRandom secureRandom;
        private final LongPasswordStrategy longPasswordStrategy;

        private Hasher(Version version, SecureRandom secureRandom, LongPasswordStrategy longPasswordStrategy) {
            this.version = version;
            this.secureRandom = secureRandom;
            this.longPasswordStrategy = longPasswordStrategy;
        }

        /**
         * Hashes given password with the OpenBSD bcrypt schema. The cost factor will define how expensive the hash will
         * be to generate. This method will use a {@link SecureRandom} to generate the internal 16 byte hash.
         * <p>
         * This implementation will add a null-terminator to the password and return a 23 byte length hash in accordance
         * with the OpenBSD implementation.
         * <p>
         * The random salt will be created internally with a {@link SecureRandom} instance.
         *
         * @param cost     exponential cost (log2 factor) between {@link #MIN_COST} and {@link #MAX_COST} e.g. 12 --&gt; 2^12 = 4,096 iterations
         * @param password to hash, will be internally converted to an utf-8 byte array representation
         * @return bcrypt hash as a char array utf-8 encoded which includes version, cost-factor, salt and the raw hash (as radix64)
         */
        public char[] hashToChar(int cost, char[] password) {
            return defaultCharset.decode(ByteBuffer.wrap(hash(cost, password))).array();
        }

        /**
         * Hashes given password with the OpenBSD bcrypt schema. The cost factor will define how expensive the hash will
         * be to generate. This method will use a {@link SecureRandom} to generate the internal 16 byte hash.
         * <p>
         * This implementation will add a null-terminator to the password and return a 23 byte length hash in accordance
         * with the OpenBSD implementation.
         * <p>
         * The random salt will be created internally with a {@link SecureRandom} instance.
         * <p>
         * This is the same as calling <code>new String(hash(cost, password), StandardCharsets.UTF-8)</code>
         *
         * @param cost     exponential cost (log2 factor) between {@link #MIN_COST} and {@link #MAX_COST} e.g. 12 --&gt; 2^12 = 4,096 iterations
         * @param password to hash, will be internally converted to an utf-8 byte array representation
         * @return bcrypt as utf-8 encoded String, which includes version, cost-factor, salt and the raw hash (as radix64)
         */
        public String hashToString(int cost, char[] password) {
            return new String(hash(cost, password), defaultCharset);
        }

        /**
         * Hashes given password with the OpenBSD bcrypt schema. The cost factor will define how expensive the hash will
         * be to generate. This method will use a {@link SecureRandom} to generate the internal 16 byte hash.
         * <p>
         * This implementation will add a null-terminator to the password and return a 23 byte length hash in accordance
         * with the OpenBSD implementation.
         * <p>
         * The random salt will be created internally with a {@link SecureRandom} instance.
         *
         * @param cost     exponential cost (log2 factor) between {@link #MIN_COST} and {@link #MAX_COST} e.g. 12 --&gt; 2^12 = 4,096 iterations
         * @param password to hash, will be internally converted to an utf-8 byte array representation
         * @return bcrypt hash utf-8 encoded byte array which includes version, cost-factor, salt and the raw hash (as radix64)
         */
        public byte[] hash(int cost, char[] password) {
            if (password == null) {
                throw new IllegalArgumentException("provided password must not be null");
            }

            byte[] passwordBytes = null;
            try {
                passwordBytes = Bytes.from(password, defaultCharset).array();
                return hash(cost, Bytes.random(SALT_LENGTH, secureRandom).array(), passwordBytes);
            } finally {
                Bytes.wrapNullSafe(passwordBytes).mutable().secureWipe();
            }
        }

        /**
         * Hashes given password with the OpenBSD bcrypt schema. The cost factor will define how expensive the hash will
         * be to generate. This method will use a {@link SecureRandom} to generate the internal 16 byte hash.
         * <p>
         * This implementation will add a null-terminator to the password and return a 23 byte length hash in accordance
         * with the OpenBSD implementation.
         * <p>
         * The random salt will be created internally with a {@link SecureRandom} instance.
         *
         * @param cost     exponential cost (log2 factor) between {@link #MIN_COST} and {@link #MAX_COST} e.g. 12 --&gt; 2^12 = 4,096 iterations
         * @param password the utf-8 encoded byte array representation
         * @return bcrypt hash utf-8 encoded byte array which includes version, cost-factor, salt and the raw hash (as radix64)
         */
        public byte[] hash(int cost, byte[] password) {
            return hash(cost, Bytes.random(SALT_LENGTH, secureRandom).array(), password);
        }

        /**
         * Hashes given password with the OpenBSD bcrypt schema. The cost factor will define how expensive the hash will
         * be to generate. This method will use given salt byte array
         * <p>
         * This implementation will add a null-terminator to the password and return a 23 byte length hash in accordance
         * with the OpenBSD implementation.
         * <p>
         * Note: This is part of the advanced APIs, only use if you know what you are doing.
         *
         * @param cost     exponential cost factor between {@link #MIN_COST} and {@link #MAX_COST} e.g. 12 --&gt; 2^12 = 4,096 iterations
         * @param salt     a random 16 byte long word, only used once
         * @param password the utf-8 encoded byte array representation
         * @return bcrypt hash utf-8 encoded byte array which includes version, cost-factor, salt and the raw hash (as radix64)
         */
        public byte[] hash(int cost, byte[] salt, byte[] password) {
            return version.formatter.createHashMessage(hashRaw(cost, salt, password));
        }

        /**
         * Hashes given password with the OpenBSD bcrypt schema. The cost factor will define how expensive the hash will
         * be to generate. This method will use given salt byte array
         * <p>
         * This implementation will add a null-terminator to the password and return a 23 byte length hash in accordance
         * with the OpenBSD implementation.
         * <p>
         * Note: This is part of the advanced APIs, only use if you know what you are doing.
         *
         * @param cost     exponential cost (log2 factor) between {@link #MIN_COST} and {@link #MAX_COST} e.g. 12 --&gt; 2^12 = 4,096 iterations
         * @param salt     a random 16 byte long word, only used once
         * @param password the utf-8 encoded byte array representation
         * @return the parts needed to parse the bcrypt hash message as raw byte arrays (salt, hash, cost, etc.)
         */
        public HashData hashRaw(int cost, byte[] salt, byte[] password) {
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

            if (!version.appendNullTerminator && password.length == 0) {
                throw new IllegalArgumentException("provided password must at least be length 1 if no null terminator is appended");
            }

            if (password.length > version.allowedMaxPwLength) {
                password = longPasswordStrategy.derive(password);
            }

            byte[] pwWithNullTerminator = version.appendNullTerminator ? Bytes.wrap(password).append((byte) 0).array() : Bytes.wrap(password).copy().array();
            // Note: pwWithNullTerminator may be longer than allowedMaxPwLength, which is not an issue because the NUL terminator
            // only plays a part with shorter passwords that need to be cyclically repeated to provide the 72 bytes of keying
            // material required by EksBlowfish key expansion.
            try {
                byte[] hash = new BCryptOpenBSDProtocol().cryptRaw(1L << (long) cost, salt, pwWithNullTerminator);
                return new HashData(cost, version, salt, version.useOnly23bytesForHash ?
                        Bytes.wrap(hash).resize(HASH_OUT_LENGTH, BytesTransformer.ResizeTransformer.Mode.RESIZE_KEEP_FROM_ZERO_INDEX).array() :
                        hash
                );
            } finally {
                Bytes.wrapNullSafe(pwWithNullTerminator).mutable().secureWipe();
            }
        }
    }

    /**
     * Holds the raw data of a bcrypt hash
     */
    public static final class HashData {
        /**
         * The cost (log2 factor) used to create the hash
         */
        public final int cost;
        /**
         * The used version
         */
        public final Version version;
        /**
         * The raw 16 bytes of the salt (not the radix64 encoded version)
         */
        public final byte[] rawSalt;
        /**
         * The raw 23 bytes of hash (not the radix64 encoded version)
         */
        public final byte[] rawHash;

        public HashData(int cost, Version version, byte[] rawSalt, byte[] rawHash) {
            Objects.requireNonNull(rawHash);
            Objects.requireNonNull(rawSalt);
            Objects.requireNonNull(version);
            if (!Bytes.wrap(rawSalt).validate(BytesValidators.exactLength(16)) ||
                    !Bytes.wrap(rawHash).validate(BytesValidators.or(BytesValidators.exactLength(23), BytesValidators.exactLength(24)))) {
                throw new IllegalArgumentException("salt must be exactly 16 bytes and hash 23 bytes long");
            }
            this.cost = cost;
            this.version = version;
            this.rawSalt = rawSalt;
            this.rawHash = rawHash;
        }

        /**
         * Internally wipe the salt and hash byte arrays
         */
        public void wipe() {
            Bytes.wrapNullSafe(rawSalt).mutable().secureWipe();
            Bytes.wrapNullSafe(rawHash).mutable().secureWipe();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            HashData hashData = (HashData) o;
            return cost == hashData.cost &&
                    version == hashData.version &&
                    Bytes.wrap(rawSalt).equalsConstantTime(hashData.rawSalt) &&
                    Bytes.wrap(rawHash).equalsConstantTime(hashData.rawHash);
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(cost, version);
            result = 31 * result + Arrays.hashCode(rawSalt);
            result = 31 * result + Arrays.hashCode(rawHash);
            return result;
        }

        @Override
        public String toString() {
            return "HashData{" +
                    "cost=" + cost +
                    ", version=" + version +
                    ", rawSalt=" + Bytes.wrap(rawSalt).encodeHex() +
                    ", rawHash=" + Bytes.wrap(rawHash).encodeHex() +
                    '}';
        }
    }

    /**
     * Can verify bcrypt hashes
     */
    public static final class Verifyer {
        private final Charset defaultCharset = DEFAULT_CHARSET;
        private final LongPasswordStrategy longPasswordStrategy;
        private final Version version;

        private Verifyer(Version version, LongPasswordStrategy longPasswordStrategy) {
            this.version = version;
            this.longPasswordStrategy = longPasswordStrategy;
        }

        /**
         * Verify given bcrypt hash, which includes salt and cost factor with given raw password requiring a specific
         * version. If the version does not match, {@link Result#verified} will be false, even if the hash matches.
         * <p>
         * If given hash has an invalid format {@link Result#validFormat} will be false; see also
         * {@link Result#formatErrorMessage} for easier debugging.
         * <p>
         * Using the strict method will also require the version identifier to match, matching hash does not suffice.
         *
         * @param password   to compare against the hash
         * @param bcryptHash to compare against the password
         * @return result object, see {@link Result} for more info
         */
        public Result verifyStrict(byte[] password, byte[] bcryptHash) {
            return innerVerifyBytes(password, bcryptHash, true);
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
            return innerVerifyBytes(password, bcryptHash, false);
        }

        /**
         * Verify given bcrypt hash, which includes salt and cost factor with given raw password requiring a specific
         * version. If the version does not match, {@link Result#verified} will be false, even if the hash matches.
         * <p>
         * If given hash has an invalid format {@link Result#validFormat} will be false; see also
         * {@link Result#formatErrorMessage} for easier debugging.
         * <p>
         * Using the strict method will also require the version identifier to match, matching hash does not suffice.
         *
         * @param password   to compare against the hash
         * @param bcryptHash to compare against the password
         * @return result object, see {@link Result} for more info
         */
        public Result verifyStrict(char[] password, char[] bcryptHash) {
            return innerVerifyChar(password, bcryptHash, true);
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
            return innerVerifyChar(password, bcryptHash, false);
        }

        /**
         * Verify given bcrypt hash, which includes salt and cost factor with given raw password.
         * The result will have {@link Result#verified} true if they match. If given hash has an
         * invalid format {@link Result#validFormat} will be false; see also {@link Result#formatErrorMessage}
         * for easier debugging.
         * <p>
         * Same as calling <code>verify(password, bcryptHash.toCharArray())</code>
         *
         * @param password   to compare against the hash
         * @param bcryptHash to compare against the password (you may just pass a regular {@link String})
         * @return result object, see {@link Result} for more info
         */
        public Result verify(char[] password, CharSequence bcryptHash) {
            return innerVerifyChar(password, toCharArray(bcryptHash), false);
        }

        /**
         * Verify given bcrypt hash, which includes salt and cost factor with given raw password.
         * The result will have {@link Result#verified} true if they match. If given hash has an
         * invalid format {@link Result#validFormat} will be false; see also {@link Result#formatErrorMessage}
         * for easier debugging.
         * <p>
         * Same as calling <code>verify(Bytes.from(password, defaultCharset).array(), bcryptHash.toCharArray())</code>
         *
         * @param password   to compare against the hash
         * @param bcryptHash to compare against the password; here the whole bcrypt hash
         *                   (including salt, etc.) in its encoded form is expected not the
         *                   raw bytes found in {@link HashData#rawHash}
         * @return result object, see {@link Result} for more info
         */
        public Result verify(char[] password, byte[] bcryptHash) {
            try (MutableBytes pw = Bytes.from(password, defaultCharset).mutable()) {
                return innerVerifyBytes(pw.array(), bcryptHash, false);
            }
        }

        /**
         * Convert a string type to char array in the most efficient manner.
         */
        private static char[] toCharArray(CharSequence charSequence) {
            if (charSequence instanceof String) {
                return charSequence.toString().toCharArray();
            } else {
                char[] buffer = new char[charSequence.length()];
                for (int i = 0; i < charSequence.length(); i++) {
                    buffer[i] = charSequence.charAt(i);
                }
                return buffer;
            }
        }

        /**
         * Verify given password against a bcryptHash with char types
         */
        private Result innerVerifyChar(char[] password, char[] bcryptHash, boolean strict) {
            byte[] passwordBytes = null;
            byte[] bcryptHashBytes = null;
            try {
                passwordBytes = Bytes.from(password, defaultCharset).array();
                bcryptHashBytes = Bytes.from(bcryptHash, defaultCharset).array();
                return innerVerifyBytes(passwordBytes, bcryptHashBytes, strict);
            } finally {
                Bytes.wrapNullSafe(passwordBytes).mutable().secureWipe();
                Bytes.wrapNullSafe(bcryptHashBytes).mutable().secureWipe();
            }
        }

        /**
         * Verify given password against a bcryptHash with byte types
         */
        private Result innerVerifyBytes(byte[] password, byte[] bcryptHash, boolean strict) {
            Objects.requireNonNull(bcryptHash);

            try {
                final Version usedVersion;
                final HashData hashData;

                if (this.version == null) {
                    hashData = Version.VERSION_2A.parser.parse(bcryptHash);
                    usedVersion = hashData.version;
                } else {
                    usedVersion = this.version;
                    hashData = usedVersion.parser.parse(bcryptHash);
                }

                if (strict) {
                    if (this.version == null) {
                        throw new IllegalArgumentException("Using strict requires to define a Version. " +
                                "Try 'BCrypt.verifier(Version.VERSION_2A)'.");
                    }
                    if (hashData.version != this.version) {
                        return new Result(hashData, false);
                    }
                }

                return verifyBCrypt(usedVersion, determinePasswordStrategy(usedVersion), password, hashData.cost, hashData.rawSalt, hashData.rawHash);
            } catch (IllegalBCryptFormatException e) {
                return new Result(e);
            }
        }

        private LongPasswordStrategy determinePasswordStrategy(Version usedVersion) {
            LongPasswordStrategy usedLongPasswordStrategy;
            if (this.longPasswordStrategy == null) {
                usedLongPasswordStrategy = LongPasswordStrategies.strict(usedVersion);
            } else {
                usedLongPasswordStrategy = this.longPasswordStrategy;
            }
            return usedLongPasswordStrategy;
        }

        /**
         * Verify given raw byte arrays of salt, 23 byte bcrypt hash and password. This is handy if the bcrypt messages are not packaged
         * in the default Modular Crypt Format (see also {@link Hasher#hashRaw(int, byte[], byte[])}).
         * <p>
         * The result will have {@link Result#verified} true if they match. If given hash has an
         * invalid format {@link Result#validFormat} will be false; see also {@link Result#formatErrorMessage}
         * for easier debugging.
         * <p>
         * Note: This is part of the advanced APIs, only use if you know what you are doing.
         *
         * @param password       to compare against the hash
         * @param bcryptHashData containing the data of the bcrypt hash (cost, salt, version, etc.)
         * @return result object, see {@link Result} for more info
         */
        public Result verify(byte[] password, HashData bcryptHashData) {
            return verify(password, bcryptHashData.cost, bcryptHashData.rawSalt, bcryptHashData.rawHash);
        }

        /**
         * Verify given raw byte arrays of salt, 23 byte bcrypt hash and password. This is handy if the bcrypt messages are not packaged
         * in the default Modular Crypt Format (see also {@link Hasher#hashRaw(int, byte[], byte[])}).
         * <p>
         * The result will have {@link Result#verified} true if they match. If given hash has an
         * invalid format {@link Result#validFormat} will be false; see also {@link Result#formatErrorMessage}
         * for easier debugging.
         * <p>
         * Note: This is part of the advanced APIs, only use if you know what you are doing.
         *
         * @param password             to compare against the hash
         * @param cost                 cost (log2 factor) which was used to create the hash
         * @param salt                 16 byte raw hash value (not radix64 version) which was used to create the hash
         * @param rawBcryptHash23Bytes 23 byte raw bcrypt hash value (not radix64 version)
         * @return result object, see {@link Result} for more info
         */
        public Result verify(byte[] password, int cost, byte[] salt, byte[] rawBcryptHash23Bytes) {
            Version usedVersion = this.version == null ? Version.VERSION_2A : this.version;
            return verifyBCrypt(usedVersion, determinePasswordStrategy(usedVersion), password, cost, salt, rawBcryptHash23Bytes);
        }

        /**
         * Raw bcrypt verification
         */
        private static Result verifyBCrypt(Version version, LongPasswordStrategy longPasswordStrategy,
                                           byte[] password, int cost, byte[] salt, byte[] rawBcryptHash23Bytes) {
            HashData hashData = BCrypt.with(Objects.requireNonNull(version), Objects.requireNonNull(longPasswordStrategy))
                    .hashRaw(cost, Objects.requireNonNull(salt), Objects.requireNonNull(password));
            return new Result(hashData, Bytes.wrap(hashData.rawHash).equalsConstantTime(Objects.requireNonNull(rawBcryptHash23Bytes)));
        }
    }

    /**
     * Result of a bcrypt hash verification
     */
    public static final class Result {
        /**
         * The parts of the modular crypt format (salt, raw hash, cost factor, version)
         */
        public final HashData details;

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

        Result(HashData details, boolean verified) {
            this(details, true, verified, null);
        }

        private Result(HashData details, boolean validFormat, boolean verified, String formatErrorMessage) {
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
     * See: <a href="https://passlib.readthedocs.io/en/stable/modular_crypt_format.html">modular_crypt_format</a>
     */
    public static final class Version {
        private static final BCryptFormatter DEFAULT_FORMATTER = new BCryptFormatter.Default(new Radix64Encoder.Default(), BCrypt.DEFAULT_CHARSET);
        private static final BCryptParser DEFAULT_PARSER = new BCryptParser.Default(new Radix64Encoder.Default(), BCrypt.DEFAULT_CHARSET);

        /**
         * Absolutely maximum length bcrypt can support (18x32bit).
         * Shorter passwords are repeated cyclically, possibly with NUL bytes separating each occurrence
         * (but the NUL byte should not count against the limit: if the password is exactly this length
         * then all characters are used and no repetition needs to happen, so no NUL needs to be inserted).
         */
        public static final int MAX_PW_LENGTH_BYTE = 72;

        /**
         * The max length of the password in bytes excluding lats null-terminator byte.
         * @deprecated this will return 71 which is not correct, the null terminator should not count towards the full length if the pw is exactly 72. Use {@link #MAX_PW_LENGTH_BYTE} instead. See <a href="https://github.com/patrickfav/bcrypt/pull/44">github</a>
         */
        @Deprecated
        public static final int DEFAULT_MAX_PW_LENGTH_BYTE = MAX_PW_LENGTH_BYTE - 1;

        /**
         * $2a$
         * <p>
         * The original specification did not define how to handle non-ASCII character, nor how to handle a null
         * terminator. The specification was revised to specify that when hashing strings:
         * - the string must be UTF-8 encoded
         * - the null terminator must be included
         */
        public static final Version VERSION_2A = new Version(new byte[]{MAJOR_VERSION, 0x61}, DEFAULT_FORMATTER, DEFAULT_PARSER);

        /**
         * $2b$ (2014/02)
         * <p>
         * A bug was discovered in the OpenBSD implementation of bcrypt. They were storing the length of their strings
         * in an unsigned char (i.e. 8-bit Byte). If a password was longer than 255 characters, it would overflow
         * and wrap at 255. To recognize possible incorrect hashes, a new version was created.
         */
        public static final Version VERSION_2B = new Version(new byte[]{MAJOR_VERSION, 0x62}, DEFAULT_FORMATTER, DEFAULT_PARSER);

        /**
         * $2x$ (2011)
         * <p>
         * Due to a bug in crypt_blowfish, a PHP implementation of BCrypt, a new version string was introduced to
         * recognize old hashes. It was mis-handling characters with the 8th bit set. Nobody else, including canonical
         * OpenBSD, adopted the idea of 2x/2y so this version marker change was limited to crypt_blowfish.
         */
        public static final Version VERSION_2X = new Version(new byte[]{MAJOR_VERSION, 0x78}, DEFAULT_FORMATTER, DEFAULT_PARSER);

        /**
         * $2y$ (2011)
         * <p>
         * See {@link #VERSION_2X}
         */
        public static final Version VERSION_2Y = new Version(new byte[]{MAJOR_VERSION, 0x79}, DEFAULT_FORMATTER, DEFAULT_PARSER);

        /**
         * $2y$ (2011) without the null terminator
         * <p>
         * See {@link #VERSION_2Y}
         */
        public static final Version VERSION_2Y_NO_NULL_TERMINATOR = new Version(new byte[]{MAJOR_VERSION, 0x79}, true, false, MAX_PW_LENGTH_BYTE, DEFAULT_FORMATTER, DEFAULT_PARSER);

        /**
         * This mirrors how Bouncy Castle creates bcrypt hashes: with 24 byte out and without null-terminator. Gets a fake
         * version descriptor.
         */
        public static final Version VERSION_BC = new Version(new byte[]{MAJOR_VERSION, 0x63}, false, false, MAX_PW_LENGTH_BYTE, DEFAULT_FORMATTER, DEFAULT_PARSER);

        /**
         * List of supported versions
         */
        public static final List<Version> SUPPORTED_VERSIONS = Collections.unmodifiableList(Arrays.asList(VERSION_2A, VERSION_2B, VERSION_2X, VERSION_2Y));

        /**
         * Version identifier byte array, eg.{0x32, 0x61} for '2a'
         */
        public final byte[] versionIdentifier;

        /**
         * Due to a bug the OpenBSD implementation only uses 23 bytes (184 bit) of the possible 24 byte output from
         * blowfish. Set this to false if you want the full 24 byte out (which makes it incompatible with most other impl)
         */
        public final boolean useOnly23bytesForHash;

        /**
         * Since OpenBSD bcrypt version $2a$ a null-terminator byte must be appended to the hash. This flag decides if
         * that will be done during hashing.
         */
        public final boolean appendNullTerminator;

        /**
         * The max allowed length of password in bcrypt, longer than that {@link LongPasswordStrategy} will be activated.
         * Usual lengths are between 50 and 72 bytes, most often are 56, 71 or 72 bytes.
         * See <a href="https://security.stackexchange.com/a/39851">security.stackexchange.com</a>
         */
        public final int allowedMaxPwLength;

        /**
         * The formatter for the bcrypt message digest
         */
        public final BCryptFormatter formatter;

        /**
         * The parser used to parse a bcrypt message
         */
        public final BCryptParser parser;

        private Version(byte[] versionIdentifier, BCryptFormatter formatter, BCryptParser parser) {
            this(versionIdentifier, true, true, MAX_PW_LENGTH_BYTE, formatter, parser);
        }

        /**
         * Create a new version. Only use this if you are know what you are doing, most common versions are already available with
         * {@link Version#VERSION_2A}, {@link Version#VERSION_2Y} etc.
         *
         * @param versionIdentifier     version as UTF-8 encoded byte array, e.g. '2a' = new byte[]{0x32, 0x61}, do not included the separator '$'
         * @param useOnly23bytesForHash set to false if you want the full 24 byte out for the hash (otherwise will be truncated to 23 byte according to OpenBSD impl)
         * @param appendNullTerminator  as defined in $2a$+ a null terminator is appended to the password, pass false if you want to avoid this
         * @param allowedMaxPwLength    the max allowed length of password in bcrypt, longer than that {@link LongPasswordStrategy} will be activated
         * @param formatter             the formatter responsible for formatting the out hash message digest
         * @param parser                responsible for parsing the message format
         */
        public Version(byte[] versionIdentifier, boolean useOnly23bytesForHash, boolean appendNullTerminator, int allowedMaxPwLength, BCryptFormatter formatter, BCryptParser parser) {
            this.versionIdentifier = versionIdentifier;
            this.useOnly23bytesForHash = useOnly23bytesForHash;
            this.appendNullTerminator = appendNullTerminator;
            this.allowedMaxPwLength = allowedMaxPwLength;
            this.formatter = formatter;
            this.parser = parser;

            if (allowedMaxPwLength > MAX_PW_LENGTH_BYTE) {
                throw new IllegalArgumentException("allowed max pw length cannot be gt " + MAX_PW_LENGTH_BYTE);
            }
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Version version = (Version) o;
            return useOnly23bytesForHash == version.useOnly23bytesForHash &&
                    appendNullTerminator == version.appendNullTerminator &&
                    allowedMaxPwLength == version.allowedMaxPwLength &&
                    Arrays.equals(versionIdentifier, version.versionIdentifier);
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(useOnly23bytesForHash, appendNullTerminator, allowedMaxPwLength);
            result = 31 * result + Arrays.hashCode(versionIdentifier);
            return result;
        }

        @Override
        public String toString() {
            return "$" + new String(versionIdentifier) + "$";
        }
    }
}
