package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;
import org.junit.Before;
import org.junit.Test;

public class BcryptTest {
    @Before
    public void setUp() {
    }


    @Test
    public void simpleTest() {
        byte[] salt = new byte[]{(byte) 156, (byte) 234, 33, 0, 5, 69, 7, 18, 9, 10, 11, 0, 13, 99, 42, 16};
        BCrypt bCrypt = BCrypt.withDefaults();
        for (int i = 4; i < 10; i++) {
            byte[] hash = bCrypt.hash(i, salt, "1234".toCharArray());
            System.out.println(Bytes.wrap(hash).encodeUtf8());
        }

    }
}
