package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

import static at.favre.lib.crypto.bcrypt.BCrypt.SEPARATOR;

/**
 * A simple parser which is able to parse Modular Crypt Format specifically for bcrypt.
 * <p>
 * It will gather the parts of the format:
 * <ul>
 * <li>version</li>
 * <li>cost factor</li>
 * <li>salt (decoded)</li>
 * <li>hash (decoded)</li>
 * </ul>
 *
 * see: {@link BCryptFormatter}
 * see: <a href="https://passlib.readthedocs.io/en/stable/modular_crypt_format.html">modular_crypt_format</a>
 */
public interface BCryptParser {

    /**
     * Read and parse given bcrypt hash
     *
     * @param bcryptHash raw UTF-8 encoded byte array of the encoded hash
     * @return decoded parts of the bcrypt hash string
     * @throws IllegalBCryptFormatException if the format is not correct Modular Crypt Format
     */
    BCrypt.HashData parse(byte[] bcryptHash) throws IllegalBCryptFormatException;

    /**
     * Default implementation
     */
    final class Default implements BCryptParser {

        private final Charset defaultCharset;
        private final Radix64Encoder encoder;

        Default(Radix64Encoder encoder, Charset defaultCharset) {
            this.defaultCharset = defaultCharset;
            this.encoder = encoder;
        }

        @Override
        public BCrypt.HashData parse(byte[] bcryptHash) throws IllegalBCryptFormatException {

            if (bcryptHash == null || bcryptHash.length == 0) {
                throw new IllegalArgumentException("must provide non-null, non-empty hash");
            }

            if (bcryptHash.length < 7) {
                throw new IllegalBCryptFormatException("hash prefix meta must be at least 7 bytes long e.g. '$2a$10$'");
            }

            ByteBuffer byteBuffer = ByteBuffer.wrap(bcryptHash);

            if (byteBuffer.get() != SEPARATOR) {
                throw new IllegalBCryptFormatException("hash must start with " + Bytes.from(SEPARATOR).encodeUtf8());
            }

            BCrypt.Version usedVersion = null;
            for (BCrypt.Version versionToTest : BCrypt.Version.SUPPORTED_VERSIONS) {
                for (int i = 0; i < versionToTest.versionIdentifier.length; i++) {
                    if (byteBuffer.get() != versionToTest.versionIdentifier[i]) {
                        byteBuffer.position(byteBuffer.position() - (i + 1));
                        break;
                    }

                    if (i == versionToTest.versionIdentifier.length - 1) {
                        usedVersion = versionToTest;
                    }
                }
                if (usedVersion != null) break;
            }

            if (usedVersion == null) {
                throw new IllegalBCryptFormatException("unknown bcrypt version");
            }

            if (byteBuffer.get() != SEPARATOR) {
                throw new IllegalBCryptFormatException("expected separator " + Bytes.from(SEPARATOR).encodeUtf8() + " after version identifier and before cost factor");
            }

            byte[] costBytes = new byte[]{byteBuffer.get(), byteBuffer.get()};

            int parsedCostFactor;
            try {
                parsedCostFactor = Integer.parseInt(new String(costBytes, defaultCharset));
            } catch (NumberFormatException e) {
                throw new IllegalBCryptFormatException("cannot parse cost factor '" + new String(costBytes, defaultCharset) + "'");
            }

            if (byteBuffer.get() != SEPARATOR) {
                throw new IllegalBCryptFormatException("expected separator " + Bytes.from(SEPARATOR).encodeUtf8() + " after cost factor");
            }

            if (bcryptHash.length != 7 + 22 + 31) {
                throw new IllegalBCryptFormatException("hash expected to be exactly 60 bytes");
            }

            byte[] salt = new byte[22];
            byte[] hash = new byte[31];
            byteBuffer.get(salt);
            byteBuffer.get(hash);

            return new BCrypt.HashData(parsedCostFactor, usedVersion, encoder.decode(salt), encoder.decode(hash));
        }
    }
}
