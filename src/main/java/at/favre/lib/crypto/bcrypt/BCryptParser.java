package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;

import java.nio.charset.Charset;

import static at.favre.lib.crypto.bcrypt.BCrypt.MAJOR_VERSION;
import static at.favre.lib.crypto.bcrypt.BCrypt.SEPARATOR;

public interface BCryptParser {

    BCrypt.HashData parse(byte[] bcryptHash) throws IllegalBCryptFormatException;

    final class Default implements BCryptParser {

        private final Charset defaultCharset;
        private final Radix64Encoder encoder;

        Default(Charset defaultCharset, Radix64Encoder encoder) {
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

            if (bcryptHash[0] != SEPARATOR || bcryptHash[1] != MAJOR_VERSION) {
                throw new IllegalBCryptFormatException("hash must start with " + new String(new byte[]{SEPARATOR, MAJOR_VERSION}));
            }

            BCrypt.Version usedVersion = null;
            for (BCrypt.Version versionToTest : BCrypt.Version.values()) {
                if (versionToTest.test(bcryptHash, true)) {
                    usedVersion = versionToTest;
                    break;
                }
            }

            if (usedVersion == null) {
                throw new IllegalBCryptFormatException("unknown bcrypt version");
            }

            byte[] costBytes = new byte[2];
            costBytes[0] = bcryptHash[usedVersion.versionPrefix.length];
            costBytes[1] = bcryptHash[usedVersion.versionPrefix.length + 1];

            int parsedCostFactor;
            try {
                parsedCostFactor = Integer.valueOf(new String(costBytes, defaultCharset));
            } catch (NumberFormatException e) {
                throw new IllegalBCryptFormatException("cannot parse cost factor '" + new String(costBytes, defaultCharset) + "'");
            }

            if (bcryptHash[usedVersion.versionPrefix.length + 2] != SEPARATOR) {
                throw new IllegalBCryptFormatException("expected separator " + Bytes.from(SEPARATOR).encodeUtf8() + " after cost factor");
            }

            if (bcryptHash.length != 7 + 22 + 31) {
                throw new IllegalBCryptFormatException("hash expected to be exactly 60 bytes");
            }

            byte[] salt = new byte[22];
            byte[] hash = new byte[31];

            System.arraycopy(bcryptHash, 7, salt, 0, salt.length);
            System.arraycopy(bcryptHash, 7 + salt.length, hash, 0, hash.length);

            return new BCrypt.HashData(parsedCostFactor, usedVersion, encoder.decode(salt), encoder.decode(hash));
        }
    }
}
