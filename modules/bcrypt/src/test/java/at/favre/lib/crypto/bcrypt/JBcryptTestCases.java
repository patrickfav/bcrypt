package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bcrypt.misc.BcryptTestEntry;
import at.favre.lib.crypto.bcrypt.misc.Repeat;
import at.favre.lib.crypto.bcrypt.misc.RepeatRule;
import org.junit.Rule;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

import static at.favre.lib.crypto.bcrypt.BcryptTest.UTF_8;
import static org.junit.Assert.assertArrayEquals;

/**
 * These are the adapted test cases from the 'original' jBcrypt implementation
 * <p>
 * See: https://github.com/jeremyh/jBCrypt/blob/master/src/test/java/org/mindrot/TestBCrypt.java
 */
public class JBcryptTestCases {
    @Rule
    public RepeatRule repeatRule = new RepeatRule();

    private final BcryptTestEntry[] testEntries = new BcryptTestEntry[]{
            new BcryptTestEntry("abc", 6, "If6bvum7DFjUnE9p2uDeDu", "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i"),
            new BcryptTestEntry("abc", 8, "Ro0CUfOqk6cXEKf3dyaM7O", "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm"),
            new BcryptTestEntry("abc", 10, "WvvTPHKwdBJ3uk0Z37EMR.", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi"),
            new BcryptTestEntry("abc", 12, "EXRkfkdmXn2gzds2SSitu.", "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q"),

            new BcryptTestEntry("a", 6, "m0CrhHm10qJ3lXRY.5zDGO", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"),
            new BcryptTestEntry("a", 8, "cfcvVd2aQ8CMvoMpP2EBfe", "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V."),
            new BcryptTestEntry("a", 10, "k87L/MF28Q673VKh8/cPi.", "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u"),
            new BcryptTestEntry("a", 12, "8NJH3LsPrANStV6XtBakCe", "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS"),

            new BcryptTestEntry("", 6, "DCq7YPn5Rq63x1Lad4cll.", "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."),
            new BcryptTestEntry("", 8, "HqWuK6/Ng6sg9gQzbLrgb.", "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye"),
            new BcryptTestEntry("", 10, "k1wbIrmNyFAPwPVPSVa/ze", "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW"),
            new BcryptTestEntry("", 12, "k42ZFHFWqBp3vWli.nIn8u", "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO"),

            new BcryptTestEntry("abcdefghijklmnopqrstuvwxyz", 6, ".rCVZVOThsIa97pEDOxvGu", "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"),
            new BcryptTestEntry("abcdefghijklmnopqrstuvwxyz", 8, "aTsUwsyowQuzRrDqFflhge", "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz."),
            new BcryptTestEntry("abcdefghijklmnopqrstuvwxyz", 10, "fVH8e28OQRj9tqiDXs1e1u", "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq"),
            new BcryptTestEntry("abcdefghijklmnopqrstuvwxyz", 12, "D4G5f18o7aMMfwasBL7Gpu", "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG"),

            new BcryptTestEntry("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", 6, "fPIsBO8qRqkjj273rfaOI.", "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO"),
            new BcryptTestEntry("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", 8, "Eq2r4G/76Wv39MzSX262hu", "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW"),
            new BcryptTestEntry("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", 10, "LgfYWkbzEvQ4JakH7rOvHe", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS"),
            new BcryptTestEntry("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", 12, "WApznUOJfkEGSmYRfnkrPO", "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC"),
    };

    @Test
    public void testAgainstReferenceHashes() {
        Date start = new Date();
        System.out.println("jBcrypt Test Vector Suite ID: " + Bytes.from(Arrays.hashCode(testEntries)).encodeHex() + " [" + testEntries.length + "] (" + start.toString() + ")");
        BcryptTestEntry.testEntries(testEntries);
        System.out.println("finished (" + (new Date().getTime() - start.getTime()) + " ms)");
    }

    @Test
    @Repeat(8)
    public void testRandomAgainstJBcrypt() throws IllegalBCryptFormatException {
        int cost = new Random().nextInt(3) + 4;
        String pw = Bytes.random(8 + new Random().nextInt(24)).encodeBase64();
        String jbcryptHash = org.mindrot.jbcrypt.BCrypt.hashpw(pw, org.mindrot.jbcrypt.BCrypt.gensalt(cost));
        BCrypt.HashData hashData = new BCryptParser.Default(new Radix64Encoder.Default(), StandardCharsets.UTF_8)
                .parse(jbcryptHash.getBytes(UTF_8));

        byte[] hash = BCrypt.with(BCrypt.Version.VERSION_2A).hash(cost, hashData.rawSalt, pw.getBytes(UTF_8));

        assertArrayEquals(jbcryptHash.getBytes(UTF_8), hash);
    }

    @Test
    @Repeat(8)
    public void testCheckPwAgainstFavreLib() {
        int cost = new Random().nextInt(5) + 4;
        String pw = "aAöoi. --~!@#$%^&*(kjlöoi" + new Random(999999999);
        byte[] hash = BCrypt.with(BCrypt.Version.VERSION_2A).hash(cost, pw.toCharArray());
        org.mindrot.jbcrypt.BCrypt.checkpw(pw, new String(hash, UTF_8));
    }
}
