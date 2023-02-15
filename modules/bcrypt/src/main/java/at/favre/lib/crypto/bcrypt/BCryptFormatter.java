package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Locale;

/**
 * Formats the out hash message of bcrypt. Usually this is the Modular Crypt Format.
 * Example
 * <pre>
 *     $2a$12$US00g/uMhoSBm.HiuieBjeMtoN69SN.GE25fCpldebzkryUyopws6
 * </pre>
 * <p>
 * Which consists of the version identifier:
 *
 * <pre>
 *     $2a$
 * </pre>
 * <p>
 * the cost factor:
 *
 * <pre>
 *     12$
 * </pre>
 * <p>
 * 16 bytes Radix64 encoded UTF-8 bytes of salt:
 *
 * <pre>
 *     uMhoSBm.HiuieBjeMtoN69
 * </pre>
 * <p>
 * and 23 Radix64 encoded UTF-8 bytes of actual bcrypt hash
 *
 * <pre>
 *     MtoN69SN.GE25fCpldebzkryUyopws6
 * </pre>
 * <p>
 * The literal <code>$</code> is a simple separator
 * <p>
 * see: <a href="https://passlib.readthedocs.io/en/stable/modular_crypt_format.html">modular_crypt_format</a>
 */
public interface BCryptFormatter {

    /**
     * Create a message for the given raw hash data
     *
     * @param hashData to create a message from
     * @return message as bytes which might be UTF-8 encoded
     */
    byte[] createHashMessage(BCrypt.HashData hashData);

    /**
     * Default implantation following the Modular Crypt Format
     */
    final class Default implements BCryptFormatter {

        private final Radix64Encoder encoder;
        private final Charset defaultCharset;

        public Default(Radix64Encoder encoder, Charset defaultCharset) {
            this.encoder = encoder;
            this.defaultCharset = defaultCharset;
        }

        @Override
        public byte[] createHashMessage(BCrypt.HashData hashData) {
            byte[] saltEncoded = encoder.encode(hashData.rawSalt);
            byte[] hashEncoded = encoder.encode(hashData.rawHash);
            byte[] costFactorBytes = String.format(Locale.US, "%02d", hashData.cost).getBytes(defaultCharset);

            try {
                ByteBuffer byteBuffer = ByteBuffer.allocate(hashData.version.versionIdentifier.length +
                        costFactorBytes.length + 3 + saltEncoded.length + hashEncoded.length);
                byteBuffer.put(BCrypt.SEPARATOR);
                byteBuffer.put(hashData.version.versionIdentifier);
                byteBuffer.put(BCrypt.SEPARATOR);
                byteBuffer.put(costFactorBytes);
                byteBuffer.put(BCrypt.SEPARATOR);
                byteBuffer.put(saltEncoded);
                byteBuffer.put(hashEncoded);
                return byteBuffer.array();
            } finally {
                Bytes.wrapNullSafe(saltEncoded).mutable().secureWipe();
                Bytes.wrapNullSafe(hashEncoded).mutable().secureWipe();
                Bytes.wrapNullSafe(costFactorBytes).mutable().secureWipe();
            }
        }
    }
}
