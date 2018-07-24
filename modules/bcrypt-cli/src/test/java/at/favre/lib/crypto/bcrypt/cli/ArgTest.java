package at.favre.lib.crypto.bcrypt.cli;

import at.favre.lib.bytes.Bytes;
import org.junit.Test;

import java.util.Random;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;

public class ArgTest {
    private final byte[] salt = Bytes.random(16, new Random(0)).array();
    private final Arg argCheck = new Arg("asdsad".toCharArray(), "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i");
    private final Arg argHash = new Arg("asdsad".toCharArray(), salt, 12);

    @Test
    public void equals() {
        assertEquals(argCheck, new Arg("asdsad".toCharArray(), "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i"));
        assertEquals(argHash, new Arg("asdsad".toCharArray(), salt, 12));
    }

    @Test
    public void testHashCode() {
        assertEquals(argCheck.hashCode(), new Arg("asdsad".toCharArray(), "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i").hashCode());
        assertEquals(argHash.hashCode(), new Arg("asdsad".toCharArray(), salt, 12).hashCode());
    }

    @Test
    public void testToString() {
        assertNotNull(argCheck.toString());
        assertNotNull(argHash.toString());
    }
}
