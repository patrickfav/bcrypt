package at.favre.lib.crypto.bcrypt;

import org.junit.Before;
import org.junit.Test;

public class Radix64Test {

    BCryptProtocol.Encoder encoder;

    @Before
    public void setUp() {
        encoder = new BCryptProtocol.Encoder.Default();
    }

    @Test
    public void testEncode() {

    }
}
