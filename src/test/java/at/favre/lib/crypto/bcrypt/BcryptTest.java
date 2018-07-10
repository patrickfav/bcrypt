package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;
import org.junit.Before;
import org.junit.Test;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

public class BcryptTest {
    private BcryptTestEntry[] testEntries = new BcryptTestEntry[]{
            // see: https://stackoverflow.com/a/12761326/774398
            new BcryptTestEntry("ππππππππ", 10, ".TtQJ4Jr6isd4Hp.mVfZeu", "$2a$10$.TtQJ4Jr6isd4Hp.mVfZeuh6Gws4rOQ/vdBczhDx.19NFK0Y84Dle"),
            // see: http://openwall.info/wiki/john/sample-hashes
            new BcryptTestEntry("password", 5, "bvIG6Nmid91Mu9RcmmWZfO", "$2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe"),
            // see: http://cvsweb.openwall.com/cgi/cvsweb.cgi/Owl/packages/glibc/crypt_blowfish/wrapper.c?rev=HEAD
            new BcryptTestEntry("U*U", 5, "CCCCCCCCCCCCCCCCCCCCC.", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"),
            new BcryptTestEntry("U*U*", 5, "CCCCCCCCCCCCCCCCCCCCC.", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"),
            new BcryptTestEntry("U*U*U", 5, "XXXXXXXXXXXXXXXXXXXXXO", "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a"),
            // new BcryptTestEntry("\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff\u0055\u00aa\u00ff", 5, "/OK.fbVrR/bpIqNJ5ianF.", "$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe"),
            //new BcryptTestEntry("\\xa3", 5, "/OK.fbVrR/bpIqNJ5ianF.", "$2a$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e"),
            //new BcryptTestEntry("$_)", 10, "O5lzwORSFzOLA2Ku1vFere", "$2a$10$O5lzwORSFzOLA2Ku1vFereqOia97MSeF8iRIhATzKqk3ozRdXmgS6")
    };

    @Before
    public void setUp() {
    }

    @Test
    public void testEntriesAgainstRef() {
        BcryptTestEntry.testEntries(testEntries);
    }

    @Test
    public void simpleTest() {
        byte[] salt = new byte[]{0x5E, (byte) 0xFA, (byte) 0xA7, (byte) 0xA3, (byte) 0xD9, (byte) 0xDF, 0x6E, (byte) 0x7F, (byte) 0x8C, 0x78, (byte) 0x96, (byte) 0xB1, 0x7B, (byte) 0xA7, 0x6E, 0x01};
        BCrypt bCrypt = BCrypt.withDefaults();
        for (int i = 4; i < 10; i++) {
            byte[] hash = bCrypt.hash(i, salt, "abcdefghijkl1234567öäü-,:".getBytes());
            assertEquals(60, hash.length);
            System.out.println(Bytes.wrap(hash).encodeUtf8());
        }
    }

    @Test
    public void verifyWithResult() {
        BCrypt bCrypt = BCrypt.withDefaults();
        byte[] pw = "78PHasdhklöALÖö".getBytes();
        byte[] hash = bCrypt.hash(8, Bytes.random(16).array(), pw);

        BCrypt.Result result = BCrypt.withDefaults().verify(pw, hash, false);
        assertTrue(result.verified);
        assertEquals(BCrypt.Version.VERSION_2A, result.details.version);
        assertEquals(8, result.details.cost);
    }

    @Test
    public void verifyIncorrectStrictVersion() {
        BCrypt bCrypt = BCrypt.with(BCrypt.Version.VERSION_2Y);
        byte[] pw = "78PHasdhklöALÖö".getBytes();
        byte[] hash = bCrypt.hash(5, Bytes.random(16).array(), pw);

        BCrypt.Result result = BCrypt.with(BCrypt.Version.VERSION_2A).verify(pw, hash, true);
        assertFalse(result.verified);
        assertEquals(BCrypt.Version.VERSION_2Y, result.details.version);
        assertEquals(5, result.details.cost);
    }
}
