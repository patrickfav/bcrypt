package at.favre.lib.crypto.bcrypt.misc;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.Radix64Encoder;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import static org.junit.Assert.assertArrayEquals;

public final class BcryptTestEntry {
    final String plainPw;
    final int cost;
    final String radix64Salt;
    final String hash;

    public BcryptTestEntry(String plainPw, int cost, String radix64Salt, String hash) {
        this.plainPw = plainPw;
        this.cost = cost;
        this.radix64Salt = radix64Salt;
        this.hash = hash;
    }

    public static void testEntries(BcryptTestEntry[] entries) {
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BcryptTestEntry that = (BcryptTestEntry) o;
        return cost == that.cost &&
                Objects.equals(plainPw, that.plainPw) &&
                Objects.equals(radix64Salt, that.radix64Salt) &&
                Objects.equals(hash, that.hash);
    }

    @Override
    public int hashCode() {

        return Objects.hash(plainPw, cost, radix64Salt, hash);
    }
}
