package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

public class BCryptParserTest {
    private BCryptParser parser;

    @Before
    public void setUp() {
        parser = new BCryptParser.Default(new Radix64Encoder.Default(), StandardCharsets.UTF_8);
    }

    @Test
    public void parseDifferentCostFactors() throws Exception {
        for (int cost = 4; cost < 10; cost++) {
            byte[] salt = Bytes.random(16).array();
            byte[] hash = BCrypt.withDefaults().hash(cost, salt, "12345".getBytes());

            BCrypt.HashData parts = parser.parse(hash);
            assertEquals(cost, parts.cost);
            assertEquals(BCrypt.Version.VERSION_2A, parts.version);
            assertArrayEquals(salt, parts.rawSalt);
            assertEquals(23, parts.rawHash.length);

            System.out.println(parts);
        }
    }

    @Test
    public void parseDifferentVersions() throws Exception {
        for (BCrypt.Version version : BCrypt.Version.SUPPORTED_VERSIONS) {
            byte[] salt = Bytes.random(16).array();
            byte[] hash = BCrypt.with(version).hash(6, salt, "hs61i1oAJhdasdÄÄ".getBytes(StandardCharsets.UTF_8));
            BCrypt.HashData parts = parser.parse(hash);
            assertEquals(version, parts.version);
            assertEquals(6, parts.cost);
            assertArrayEquals(salt, parts.rawSalt);
            assertEquals(23, parts.rawHash.length);

            System.out.println(parts);
        }
    }

    @Test
    public void parseDoubleDigitCost() throws Exception {
        byte[] salt = Bytes.random(16).array();
        byte[] hash = BCrypt.with(BCrypt.Version.VERSION_2A).hash(11, salt, "i27ze8172eaidh asdhsd".getBytes(StandardCharsets.UTF_8));
        BCrypt.HashData parts = parser.parse(hash);
        assertEquals(BCrypt.Version.VERSION_2A, parts.version);
        assertEquals(11, parts.cost);
        assertArrayEquals(salt, parts.rawSalt);
        assertEquals(23, parts.rawHash.length);

        System.out.println(parts);
    }

    @Test(expected = IllegalBCryptFormatException.class)
    public void parseErrorMissingVersion() throws Exception {
        parser.parse("$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i".getBytes());
    }

    @Test(expected = IllegalBCryptFormatException.class)
    public void parseErrorMissingLeadingZero() throws Exception {
        parser.parse("$2a$6$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i".getBytes());
    }

    @Test(expected = IllegalBCryptFormatException.class)
    public void parseErrorMissingSeparator() throws Exception {
        parser.parse("$2a$06If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i".getBytes());
    }

    @Test(expected = IllegalBCryptFormatException.class)
    public void parseErrorMissingSeparator2() throws Exception {
        parser.parse("$2a06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i".getBytes());
    }

    @Test(expected = IllegalBCryptFormatException.class)
    public void parseErrorInvalidVersion() throws Exception {
        parser.parse("$2$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i".getBytes());
    }

    @Test(expected = IllegalBCryptFormatException.class)
    public void parseErrorInvalidVersion2() throws Exception {
        parser.parse("$3a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i".getBytes());
    }

    @Test(expected = IllegalBCryptFormatException.class)
    public void parseErrorInvalidVersion3() throws Exception {
        parser.parse("$2l$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i".getBytes());
    }

    @Test(expected = IllegalBCryptFormatException.class)
    public void parseErrorMissingSaltAndHas() throws Exception {
        parser.parse("$2a$06$".getBytes());
    }

    @Test(expected = IllegalBCryptFormatException.class)
    public void parseErrorMissingHash() throws Exception {
        parser.parse("$2a$06$If6bvum7DFjUnE9p2uDeDu".getBytes());
    }

    @Test(expected = IllegalBCryptFormatException.class)
    public void parseErrorMissingChar() throws Exception {
        parser.parse("$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0".getBytes());
    }

    @Test(expected = IllegalBCryptFormatException.class)
    public void parseErrorTooLong() throws Exception {
        parser.parse("$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i9".getBytes());
    }

    @Test(expected = IllegalArgumentException.class)
    public void parseErrorNullHash() throws Exception {
        parser.parse(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void parseErrorZeroLengthHash() throws Exception {
        parser.parse(new byte[0]);
    }

    @Test(expected = IllegalBCryptFormatException.class)
    public void parseErrorWayTooShort() throws Exception {
        parser.parse("$2a".getBytes());
    }

    @Test
    public void parseErrorTooLongGetExceptionMessage() {
        try {
            parser.parse("$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i9".getBytes());
            fail();
        } catch (IllegalBCryptFormatException e) {
            assertNotNull(e.getMessage());
            assertTrue(e.getMessage().length() > 20);
            System.out.println(e.getMessage());
        }
    }
}
