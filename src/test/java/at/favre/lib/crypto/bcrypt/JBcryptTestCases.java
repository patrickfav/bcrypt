package at.favre.lib.crypto.bcrypt;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertArrayEquals;

/**
 * These are the adapted test cases from the 'original' jBcrypt implementation
 * <p>
 * See: https://github.com/jeremyh/jBCrypt/blob/master/src/test/java/org/mindrot/TestBCrypt.java
 */
public class JBcryptTestCases {

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
            new BcryptTestEntry("", 12, "k42ZFHFWqBp3vWli.nIn8u/ze", "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO"),

            new BcryptTestEntry("abcdefghijklmnopqrstuvwxyz", 6, ".rCVZVOThsIa97pEDOxvGu", "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"),
            new BcryptTestEntry("abcdefghijklmnopqrstuvwxyz", 8, "aTsUwsyowQuzRrDqFflhge", "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz."),
            new BcryptTestEntry("abcdefghijklmnopqrstuvwxyz", 10, "fVH8e28OQRj9tqiDXs1e1u", "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq"),
            new BcryptTestEntry("abcdefghijklmnopqrstuvwxyz", 12, "D4G5f18o7aMMfwasBL7Gpu.", "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG"),

            new BcryptTestEntry("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", 6, "fPIsBO8qRqkjj273rfaOI.", "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO"),
            new BcryptTestEntry("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", 8, "Eq2r4G/76Wv39MzSX262hu", "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW"),
            new BcryptTestEntry("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", 10, "LgfYWkbzEvQ4JakH7rOvHe", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS"),
            new BcryptTestEntry("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", 12, "WApznUOJfkEGSmYRfnkrPO", "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC"),
    };

    /**
     * Test method for 'BCrypt.hashpw(String, String)'
     */
    @Test
    public void testAgainstReferenceHashes() {
        for (BcryptTestEntry testEntry : testEntries) {
            byte[] hashed = BCrypt.withDefaults().hash(testEntry.cost, new BCryptProtocol.Encoder.Default().decode(testEntry.radix64Salt, 16), testEntry.plainPw.toCharArray());
            assertArrayEquals("hash does not match: \n\r" + testEntry.hash + " was \n\r" + new String(hashed, StandardCharsets.UTF_8),
                    testEntry.hash.getBytes(StandardCharsets.UTF_8), hashed);
        }
    }

//    /**
//     * Test method for 'BCrypt.gensalt(int)'
//     */
//    public void testGensaltInt() {
//        System.out.print("BCrypt.gensalt(log_rounds):");
//        for (int i = 4; i <= 12; i++) {
//            System.out.print(" " + Integer.toString(i) + ":");
//            for (int j = 0; j < test_vectors.length; j += 4) {
//                String plain = test_vectors[j][0];
//                String salt = BCrypt.gensalt(i);
//                String hashed1 = BCrypt.hashpw(plain, salt);
//                String hashed2 = BCrypt.hashpw(plain, hashed1);
//                assertEquals(hashed1, hashed2);
//                System.out.print(".");
//            }
//        }
//        System.out.println("");
//    }
//
//    /**
//     * Test method for 'BCrypt.gensalt()'
//     */
//    public void testGensalt() {
//        System.out.print("BCrypt.gensalt(): ");
//        for (int i = 0; i < test_vectors.length; i += 4) {
//            String plain = test_vectors[i][0];
//            String salt = BCrypt.gensalt();
//            String hashed1 = BCrypt.hashpw(plain, salt);
//            String hashed2 = BCrypt.hashpw(plain, hashed1);
//            assertEquals(hashed1, hashed2);
//            System.out.print(".");
//        }
//        System.out.println("");
//    }
//
//    /**
//     * Test method for 'BCrypt.checkpw(String, String)'
//     * expecting success
//     */
//    public void testCheckpw_success() {
//        System.out.print("BCrypt.checkpw w/ good passwords: ");
//        for (int i = 0; i < test_vectors.length; i++) {
//            String plain = test_vectors[i][0];
//            String expected = test_vectors[i][2];
//            assertTrue(BCrypt.checkpw(plain, expected));
//            System.out.print(".");
//        }
//        System.out.println("");
//    }
//
//    /**
//     * Test method for 'BCrypt.checkpw(String, String)'
//     * expecting failure
//     */
//    public void testCheckpw_failure() {
//        System.out.print("BCrypt.checkpw w/ bad passwords: ");
//        for (int i = 0; i < test_vectors.length; i++) {
//            int broken_index = (i + 4) % test_vectors.length;
//            String plain = test_vectors[i][0];
//            String expected = test_vectors[broken_index][2];
//            assertFalse(BCrypt.checkpw(plain, expected));
//            System.out.print(".");
//        }
//        System.out.println("");
//    }
//
//    /**
//     * Test for correct hashing of non-US-ASCII passwords
//     */
//    public void testInternationalChars() {
//        System.out.print("BCrypt.hashpw w/ international chars: ");
//        String pw1 = "\u2605\u2605\u2605\u2605\u2605\u2605\u2605\u2605";
//        String pw2 = "????????";
//
//        String h1 = BCrypt.hashpw(pw1, BCrypt.gensalt());
//        assertFalse(BCrypt.checkpw(pw2, h1));
//        System.out.print(".");
//
//        String h2 = BCrypt.hashpw(pw2, BCrypt.gensalt());
//        assertFalse(BCrypt.checkpw(pw1, h2));
//        System.out.print(".");
//        System.out.println("");
//    }
}
