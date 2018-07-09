package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Objects;

import static at.favre.lib.crypto.bcrypt.BCrypt.MAJOR_VERSION;
import static at.favre.lib.crypto.bcrypt.BCrypt.SEPARATOR;

public interface BCryptParser {

    Parts parse(byte[] bcryptHash) throws IllegalBCryptFormatException;

    final class Default implements BCryptParser {

        private final Charset defaultCharset;
        private final BCryptProtocol.Encoder encoder;

        Default(Charset defaultCharset, BCryptProtocol.Encoder encoder) {
            this.defaultCharset = defaultCharset;
            this.encoder = encoder;
        }

        @Override
        public Parts parse(byte[] bcryptHash) throws IllegalBCryptFormatException {
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

            return new Parts(usedVersion, parsedCostFactor,
                    encoder.decode(new String(salt), salt.length),
                    encoder.decode(new String(hash), hash.length));
        }
    }

    final class Parts {
        public final BCrypt.Version version;
        public final int cost;
        public final byte[] salt;
        public final byte[] hash;

        Parts(BCrypt.Version version, int cost, byte[] salt, byte[] hash) {
            this.version = version;
            this.cost = cost;
            this.salt = salt;
            this.hash = hash;
        }

        @Override
        public String toString() {
            return "Parts{" +
                    "version=" + version +
                    ", cost=" + cost +
                    ", salt=" + Bytes.wrap(salt).toString() +
                    ", hash=" + Bytes.wrap(hash).toString() +
                    '}';
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Parts parts = (Parts) o;
            return cost == parts.cost &&
                    version == parts.version &&
                    Arrays.equals(salt, parts.salt) &&
                    Arrays.equals(hash, parts.hash);
        }

        @Override
        public int hashCode() {

            int result = Objects.hash(version, cost);
            result = 31 * result + Arrays.hashCode(salt);
            result = 31 * result + Arrays.hashCode(hash);
            return result;
        }
    }
}
