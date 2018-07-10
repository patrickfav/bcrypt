package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class Radix64Test {

    Radix64Encoder encoder;

    @Before
    public void setUp() {
        encoder = new Radix64Encoder.Default();
    }

    @Test
    public void testEncode() {
        for (int i = 1; i < 128; i++) {
            byte[] rnd = Bytes.random(i).array();
            byte[] encoded = encoder.encode(rnd, rnd.length);
            byte[] decoded = encoder.decode(encoded);

            assertArrayEquals(rnd, decoded);
            System.out.println(Bytes.wrap(encoded).encodeUtf8());
        }

    }
}
