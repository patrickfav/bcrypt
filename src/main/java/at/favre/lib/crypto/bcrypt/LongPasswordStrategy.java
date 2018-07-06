package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.bytes.BytesTransformer;

import static at.favre.lib.crypto.bcrypt.BCrypt.MAX_PW_LENGTH_BYTE;

/**
 * Strategy if the password is longer that support by Bcrypt itself (71 bytes + null terminator with $2a$)
 */
public interface LongPasswordStrategy {

    byte[] derive(byte[] rawPassword);

    /**
     * This strategy will always throw an exception to force passwords under the max length
     */
    final class StrictMaxPasswordLengthStrategy implements LongPasswordStrategy {
        @Override
        public byte[] derive(byte[] rawPassword) {
            throw new IllegalArgumentException("password must not be longer than " + MAX_PW_LENGTH_BYTE + " bytes plus null terminator encoded in utf-8, was " + rawPassword.length);
        }
    }

    /**
     * Will use sha512 to hash given password to generate fixed 64 byte length hash value
     */
    final class Sha512DerivationStrategy implements LongPasswordStrategy {
        @Override
        public byte[] derive(byte[] rawPassword) {
            return Bytes.wrap(rawPassword).hash("SHA-512").array();
        }
    }

    /**
     * Truncates the password the max possible length.
     * <p>
     * NOTE: This is not recommended, only for compatibility with current hashes; uses {@link Sha512DerivationStrategy}
     * if you need to support passwords with arbitrary lengths.
     */
    final class TruncateStrategy implements LongPasswordStrategy {
        @Override
        public byte[] derive(byte[] rawPassword) {
            return Bytes.wrap(rawPassword).resize(MAX_PW_LENGTH_BYTE, BytesTransformer.ResizeTransformer.Mode.RESIZE_KEEP_FROM_ZERO_INDEX).array();
        }
    }

}
