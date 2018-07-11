package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.bytes.BytesTransformer;
import at.favre.lib.crypto.bcrypt.misc.Repeat;
import at.favre.lib.crypto.bcrypt.misc.RepeatRule;
import org.junit.Rule;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Random;

import static at.favre.lib.crypto.bcrypt.BcryptTest.UTF_8;
import static org.junit.Assert.assertArrayEquals;

/**
 * Tests against the Bouncy Castle implementation of BCrypt
 * <p>
 * See: https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/crypto/generators/BCrypt.java
 */
public class BcBcryptTestCases {
    @Rule
    public RepeatRule repeatRule = new RepeatRule();

    @Test
    @Repeat(10)
    public void testRandomAgainstJBcrypt() throws IllegalBCryptFormatException {
        int cost = new Random().nextInt(3) + 4;
        String pw = Bytes.random(8 + new Random().nextInt(24)).encodeBase64();
        byte[] salt = Bytes.random(16).array();

        //BC will only return the hash without the salt, cost factor and version identifier and does not add a null terminator
        byte[] bcryptHashOnly = org.bouncycastle.crypto.generators.BCrypt.generate(Bytes.from(pw).append((byte) 0).array(), salt, cost);

        byte[] hash = BCrypt.with(BCrypt.Version.VERSION_2A).hash(cost, salt, pw.getBytes(UTF_8));
        BCrypt.HashData parts = new BCryptParser.Default(StandardCharsets.UTF_8, new Radix64Encoder.Default()).parse(hash);

        assertArrayEquals(parts.rawHash, Bytes.wrap(bcryptHashOnly).resize(23, BytesTransformer.ResizeTransformer.Mode.RESIZE_KEEP_FROM_ZERO_INDEX).array());
    }
}
