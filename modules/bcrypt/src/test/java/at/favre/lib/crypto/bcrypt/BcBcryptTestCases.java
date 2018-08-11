package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bcrypt.misc.Repeat;
import at.favre.lib.crypto.bcrypt.misc.RepeatRule;
import org.junit.Rule;
import org.junit.Test;

import java.util.Arrays;
import java.util.Date;
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

    // see: https://www.programcreek.com/java-api-examples/?code=ttt43ttt/gwt-crypto/gwt-crypto-master/src/test/java/org/bouncycastle/crypto/test/BCryptTest.java
    private static final Object[][] testVectors = {
            {"00", "144b3d691a7b4ecf39cf735c7fa7a79c", 6, "557e94f34bf286e8719a26be94ac1e16d95ef9f819dee092"},
            {"00", "26c63033c04f8bcba2fe24b574db6274", 8, "56701b26164d8f1bc15225f46234ac8ac79bf5bc16bf48ba"},
            {"00", "9b7c9d2ada0fd07091c915d1517701d6", 10, "7b2e03106a43c9753821db688b5cc7590b18fdf9ba544632"},
            {"6100", "a3612d8c9a37dac2f99d94da03bd4521", 6, "e6d53831f82060dc08a2e8489ce850ce48fbf976978738f3"},
            {"6100", "7a17b15dfe1c4be10ec6a3ab47818386", 8, "a9f3469a61cbff0a0f1a1445dfe023587f38b2c9c40570e1"},
            {"6100", "9bef4d04e1f8f92f3de57323f8179190", 10, "5169fd39606d630524285147734b4c981def0ee512c3ace1"},
            {"61626300", "2a1f1dc70a3d147956a46febe3016017", 6, "d9a275b493bcbe1024b0ff80d330253cfdca34687d8f69e5"},
            {"61626300", "4ead845a142c9bc79918c8797f470ef5", 8, "8d4131a723bfbbac8a67f2e035cae08cc33b69f37331ea91"},
            {"61626300", "631c554493327c32f9c26d9be7d18e4c", 10, "8cd0b863c3ff0860e31a2b42427974e0283b3af7142969a6"},
            {"6162636465666768696a6b6c6d6e6f707172737475767778797a00", "02d1176d74158ee29cffdac6150cf123", 6, "4d38b523ce9dc6f2f6ff9fb3c2cd71dfe7f96eb4a3baf19f"},
            {"6162636465666768696a6b6c6d6e6f707172737475767778797a00", "715b96caed2ac92c354ed16c1e19e38a", 8, "98bf9ffc1f5be485f959e8b1d526392fbd4ed2d5719f506b"},
            {"6162636465666768696a6b6c6d6e6f707172737475767778797a00", "85727e838f9049397fbec90566ede0df", 10, "cebba53f67bd28af5a44c6707383c231ac4ef244a6f5fb2b"},
            {"7e21402324255e262a28292020202020207e21402324255e262a2829504e4246524400", "8512ae0d0fac4ec9a5978f79b6171028", 6, "26f517fe5345ad575ba7dfb8144f01bfdb15f3d47c1e146a"},
            {"7e21402324255e262a28292020202020207e21402324255e262a2829504e4246524400", "1ace2de8807df18c79fced54678f388f", 8, "d51d7cdf839b91a25758b80141e42c9f896ae80fd6cd561f"},
            {"7e21402324255e262a28292020202020207e21402324255e262a2829504e4246524400", "36285a6267751b14ba2dc989f6d43126", 10, "db4fab24c1ff41c1e2c966f8b3d6381c76e86f52da9e15a9"},
            {"c2a300", "144b3d691a7b4ecf39cf735c7fa7a79c", 6, "5a6c4fedb23980a7da9217e0442565ac6145b687c7313339"}};

    @Test
    @Repeat(10)
    public void testRandomAgainstJBcrypt() {
        int cost = new Random().nextInt(3) + 4;
        String pw = Bytes.random(8 + new Random().nextInt(24)).encodeBase64();
        byte[] salt = Bytes.random(16).array();

        //BC will only return the hash without the salt, cost factor and version identifier and does not add a null terminator
        byte[] bcryptHashOnly = org.bouncycastle.crypto.generators.BCrypt.generate(Bytes.from(pw).array(), salt, cost);
        BCrypt.HashData hash = BCrypt.with(BCrypt.Version.VERSION_BC).hashRaw(cost, salt, pw.getBytes(UTF_8));
        assertArrayEquals(hash.rawHash, bcryptHashOnly);
    }

    @Test
    public void testBcRefVectors() {
        Date start = new Date();
        System.out.println("Bouncy Castle Test Vector Suite ID: " + Bytes.from(Arrays.hashCode(testVectors)).encodeHex() + " [" + testVectors.length + "] (" + start.toString() + ")");
        for (Object[] testVector : testVectors) {
            byte[] pw = Bytes.parseHex((String) testVector[0]).array();
            byte[] salt = Bytes.parseHex((String) testVector[1]).array();
            int cost = (int) testVector[2];
            byte[] refHash = Bytes.parseHex((String) testVector[3]).array();

            BCrypt.HashData hash = BCrypt.with(BCrypt.Version.VERSION_BC).hashRaw(cost, salt, pw);
            assertArrayEquals(refHash, hash.rawHash);
        }
        System.out.println("finished (" + (new Date().getTime() - start.getTime()) + " ms)");
    }
}
