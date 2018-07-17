package at.favre.lib.crypto.bcrypt;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertArrayEquals;

final class BcryptTestEntry {
    final String plainPw;
    final int cost;
    final String radix64Salt;
    final String hash;

    BcryptTestEntry(String plainPw, int cost, String radix64Salt, String hash) {
        this.plainPw = plainPw;
        this.cost = cost;
        this.radix64Salt = radix64Salt;
        this.hash = hash;
    }

    static void testEntries(BcryptTestEntry[] entries) {
        for (BcryptTestEntry testEntry : entries) {
            byte[] hashed = BCrypt.withDefaults().hash(
                    testEntry.cost,
                    new Radix64Encoder.Default().decode(testEntry.radix64Salt.getBytes(StandardCharsets.UTF_8)),
                    testEntry.plainPw.getBytes(StandardCharsets.UTF_8));

            assertArrayEquals(
                    "hash does not match: \n\r" + testEntry.hash + " was \n\r" + new String(hashed, StandardCharsets.UTF_8),
                    testEntry.hash.getBytes(StandardCharsets.UTF_8), hashed);
        }
    }
}
