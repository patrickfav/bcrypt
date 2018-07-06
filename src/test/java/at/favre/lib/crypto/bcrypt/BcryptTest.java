package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.BCryptProtocol;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

public class BcryptTest {
    @Before
    public void setUp() {
    }


    @Test
    public void simpleTest() {
        byte[] salt = new byte[]{(byte) 156, (byte) 234, 33, 0, 5, 69, 7, 18, 9, 10, 11, 0, 13, 99, 42, 16};
        BCrypt bCrypt = new BCrypt(BCrypt.Version.VERSION_2A, new SecureRandom(), new BCryptProtocol.Radix64Encoder());
        for (int i = 4; i < 10; i++) {
            byte[] hash = bCrypt.hash(i, salt, "1234".toCharArray());
            System.out.println(Bytes.wrap(hash).encodeUtf8());
        }

    }
}
