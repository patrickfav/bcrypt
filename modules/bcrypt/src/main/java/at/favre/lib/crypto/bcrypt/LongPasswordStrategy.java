package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.bytes.BytesTransformer;

/**
 * Strategy if the password is longer than supported by Bcrypt itself (71 bytes + null terminator with $2a$)
 */
public interface LongPasswordStrategy {

    /**
     * Derives (hashes, shortens, etc) the given password to a desired max length.
     *
     * @param rawPassword to check and derive
     * @return the derived (shortened) password, or the same reference if short enough
     */
    byte[] derive(byte[] rawPassword);

    /**
     * Default base implementation
     */
    abstract class BaseLongPasswordStrategy implements LongPasswordStrategy {
        final int maxLength;

        private BaseLongPasswordStrategy(int maxLength) {
            this.maxLength = maxLength;
        }

        abstract byte[] innerDerive(byte[] input);

        @Override
        public byte[] derive(byte[] rawPassword) {
            if (rawPassword.length >= maxLength) {
                return innerDerive(rawPassword);
            }
            return rawPassword;
        }
    }

    /**
     * This strategy will always throw an exception to force passwords under the max length
     */
    final class StrictMaxPasswordLengthStrategy extends BaseLongPasswordStrategy {
        StrictMaxPasswordLengthStrategy(int maxLength) {
            super(maxLength);
        }

        @Override
        public byte[] innerDerive(byte[] rawPassword) {
            throw new IllegalArgumentException("password must not be longer than " + maxLength + " bytes plus null terminator encoded in utf-8, was " + rawPassword.length);
        }
    }

    /**
     * Will use sha512 to hash given password to generate fixed 64 byte length hash value
     */
    final class Sha512DerivationStrategy extends BaseLongPasswordStrategy {
        Sha512DerivationStrategy(int maxLength) {
            super(maxLength);
        }

        @Override
        public byte[] innerDerive(byte[] rawPassword) {
            return Bytes.wrap(rawPassword).hash("SHA-512").array();
        }
    }

    /**
     * Truncates the password the max possible length.
     * <p>
     * NOTE: This is not recommended, only for compatibility with current hashes; uses {@link Sha512DerivationStrategy}
     * if you need to support passwords with arbitrary lengths.
     */
    final class TruncateStrategy extends BaseLongPasswordStrategy {

        TruncateStrategy(int maxLength) {
            super(maxLength);
        }

        @Override
        public byte[] innerDerive(byte[] rawPassword) {
            return Bytes.wrap(rawPassword).resize(maxLength, BytesTransformer.ResizeTransformer.Mode.RESIZE_KEEP_FROM_ZERO_INDEX).array();
        }
    }

    /**
     * A simple strategy that just returns the provided password without changing it.
     */
    final class PassThroughStrategy implements LongPasswordStrategy {
        @Override
        public byte[] derive(byte[] rawPassword) {
            return rawPassword;
        }
    }
}
