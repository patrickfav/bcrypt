package at.favre.lib.crypto.bcrypt;

import java.nio.charset.Charset;

import static at.favre.lib.crypto.bcrypt.BCrypt.MAJOR_VERSION;
import static at.favre.lib.crypto.bcrypt.BCrypt.SEPARATOR;

public interface BCryptParser {

    Parts parse(byte[] bcryptHash);

    final class Default implements BCryptParser {

        public final Charset defaultCharset;

        public Default(Charset defaultCharset) {
            this.defaultCharset = defaultCharset;
        }

        @Override
        public Parts parse(byte[] bcryptHash) {
            if (bcryptHash == null || bcryptHash.length == 0) {
                throw new IllegalArgumentException("must provide non-null, non-empty hash");
            }

            if (bcryptHash.length < 7) {
                throw new IllegalBCryptFormatException("hash prefix meta must be at least 6 bytes long e.g. '$2a$10$'");
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
            costBytes[0] = bcryptHash[usedVersion.versionPrefix.length - 1];
            costBytes[1] = bcryptHash[usedVersion.versionPrefix.length];

            int parsedCostFactor;
            try {
                parsedCostFactor = Integer.valueOf(new String(costBytes, defaultCharset));
            } catch (NumberFormatException e) {
                throw new IllegalBCryptFormatException("cannot parse cost factor '" + new String(costBytes, defaultCharset) + "'");
            }

            if (bcryptHash[usedVersion.versionPrefix.length + 1] != SEPARATOR) {
                throw new IllegalBCryptFormatException("expected separator " + SEPARATOR + " after cost factor");
            }

            /*for (int i = ; i <; i++) {

            }*/

            return new Parts(usedVersion, parsedCostFactor, null, null);
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
    }
}
