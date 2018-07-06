package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;
import org.junit.Before;
import org.junit.Test;

public class BcryptTest {
    // see: https://stackoverflow.com/a/12761326/774398
    private final BcryptTestEntry unicodeTestEntry = new BcryptTestEntry("ππππππππ", 10, ".TtQJ4Jr6isd4Hp.mVfZeu", "$2a$10$.TtQJ4Jr6isd4Hp.mVfZeuh6Gws4rOQ/vdBczhDx.19NFK0Y84Dle");

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
