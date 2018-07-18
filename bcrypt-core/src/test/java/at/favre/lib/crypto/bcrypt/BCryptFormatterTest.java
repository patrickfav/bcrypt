package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bcrypt.misc.Repeat;
import at.favre.lib.crypto.bcrypt.misc.RepeatRule;
import org.junit.Rule;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Random;

import static at.favre.lib.crypto.bcrypt.BcryptTest.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class BCryptFormatterTest {

    @Rule
    public RepeatRule repeatRule = new RepeatRule();
    private final BCryptFormatter formatter = new BCryptFormatter.Default(new Radix64Encoder.Default(), UTF_8);
    private final BCryptParser parser = new BCryptParser.Default(new Radix64Encoder.Default(), UTF_8);

    @Test
    @Repeat(25)
    public void createRandomMessageAndVerify() throws IllegalBCryptFormatException {
        int cost = new Random().nextInt(27) + 4;
        byte[] salt = Bytes.random(16).array();
        byte[] hash = Bytes.random(23).array();
        BCrypt.Version version = BCrypt.Version.SUPPORTED_VERSIONS.get(new Random().nextInt(BCrypt.Version.SUPPORTED_VERSIONS.size()));
        BCrypt.HashData hashData = new BCrypt.HashData(cost, version, salt, hash);
        byte[] bcryptHash = formatter.createHashMessage(hashData);
        BCrypt.HashData parsed = parser.parse(bcryptHash);

        assertEquals(hashData, parsed);
    }

    @Test
    public void testAgainstReferenceHash1() {
        testAgainstReferenceHash(
                new BCrypt.HashData(6, BCrypt.Version.VERSION_2A,
                        new byte[]{0x14, 0x4B, 0x3D, 0x69, 0x1A, 0x7B, 0x4E, (byte) 0xCF, 0x39, (byte) 0xCF, 0x73, 0x5C, (byte) 0x7F, (byte) 0xA7, (byte) 0xA7, (byte) 0x9C},
                        new byte[]{0x55, 0x7E, (byte) 0x94, (byte) 0xF3, 0x4B, (byte) 0xF2, (byte) 0x86, (byte) 0xE8, 0x71, (byte) 0x9A, 0x26, (byte) 0xBE, (byte) 0x94, (byte) 0xAC, 0x1E, 0x16, (byte) 0xD9, 0x5E, (byte) 0xF9, (byte) 0xF8, 0x19, (byte) 0xDE, (byte) 0xE0}),
                "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."
        );
    }

    @Test
    public void testAgainstReferenceHash2() {
        testAgainstReferenceHash(
                new BCrypt.HashData(12, BCrypt.Version.VERSION_2Y,
                        new byte[]{0x17, (byte) 0xA2, 0x3B, (byte) 0x87, (byte) 0x7F, (byte) 0xAA, (byte) 0xF5, (byte) 0xC3, (byte) 0x8E, (byte) 0x87, 0x27, 0x2E, 0x0C, (byte) 0xDF, 0x48, (byte) 0xAF},
                        new byte[]{0x49, (byte) 0x8C, 0x11, (byte) 0xE6, (byte) 0xB9, (byte) 0xAD, 0x6E, (byte) 0xD4, 0x02, (byte) 0xA6, (byte) 0xC4, 0x40, 0x76, (byte) 0x88, 0x35, 0x74, (byte) 0xEA, 0x62, 0x01, 0x2C, (byte) 0x8B, 0x06, (byte) 0xB2}),
                "$2y$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG"
        );
    }

    @Test
    public void testAgainstReferenceHash3() {
        testAgainstReferenceHash(
                new BCrypt.HashData(8, BCrypt.Version.VERSION_2B,
                        new byte[]{0x26, (byte) 0xC6, 0x30, 0x33, (byte) 0xC0, 0x4F, (byte) 0x8B, (byte) 0xCB, (byte) 0xA2, (byte) 0xFE, 0x24, (byte) 0xB5, 0x74, (byte) 0xDB, 0x62, 0x74},
                        new byte[]{0x56, 0x70, 0x1B, 0x26, 0x16, 0x4D, (byte) 0x8F, 0x1B, (byte) 0xC1, 0x52, 0x25, (byte) 0xF4, 0x62, 0x34, (byte) 0xAC, (byte) 0x8A, (byte) 0xC7, (byte) 0x9B, (byte) 0xF5, (byte) 0xBC, 0x16, (byte) 0xBF, 0x48}),
                "$2b$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye"
        );
    }

    private void testAgainstReferenceHash(BCrypt.HashData hashData, String refHash) {
        byte[] bcryptHash = formatter.createHashMessage(hashData);
        assertArrayEquals(refHash.getBytes(StandardCharsets.UTF_8), bcryptHash);
    }
}
