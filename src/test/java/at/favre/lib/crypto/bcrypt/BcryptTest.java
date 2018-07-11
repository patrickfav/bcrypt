package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;
import org.junit.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

public class BcryptTest {
    public final static Charset UTF_8 = StandardCharsets.UTF_8;
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

    @Test
    public void testEntriesAgainstRef() {
        BcryptTestEntry.testEntries(testEntries);
    }

    @Test
    public void quickStart() {
        String password = "1234";
        char[] bcryptChars = BCrypt.withDefaults().hashToChar(12, password.toCharArray());
        String bcryptHashString = new String(bcryptChars);
        System.out.println(bcryptHashString);
        BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), bcryptChars);
        assertTrue(result.verified);
    }

    @Test
    public void testSimpleBcryptHashes() {
        byte[] salt = new byte[]{0x5E, (byte) 0xFA, (byte) 0xA7, (byte) 0xA3, (byte) 0xD9, (byte) 0xDF, 0x6E, (byte) 0x7F, (byte) 0x8C, 0x78, (byte) 0x96, (byte) 0xB1, 0x7B, (byte) 0xA7, 0x6E, 0x01};
        BCrypt.Hasher bCrypt = BCrypt.withDefaults();
        for (int i = 4; i < 10; i++) {
            byte[] hash = bCrypt.hash(i, salt, "abcdefghijkl1234567öäü-,:".getBytes());
            assertEquals(60, hash.length);
            System.out.println(Bytes.wrap(hash).encodeUtf8());
        }
    }

    @Test
    public void testHashAllVersions() {
        for (BCrypt.Version version : BCrypt.Version.values()) {
            checkHash(BCrypt.with(version));
        }
    }

    @Test
    public void testSecureRandom() {
        checkHash(BCrypt.with(new SecureRandom()));
    }

    @Test
    public void testLongPasswordStrategy() {
        checkHash(BCrypt.with(new LongPasswordStrategy.TruncateStrategy(BCrypt.MAX_PW_LENGTH_BYTE)));
    }

    @Test
    public void testFullyCustom() {
        checkHash(BCrypt.with(BCrypt.Version.VERSION_2Y, new SecureRandom(), new LongPasswordStrategy.TruncateStrategy(BCrypt.MAX_PW_LENGTH_BYTE)));
    }

    private void checkHash(BCrypt.Hasher bCrypt) {
        BCrypt.Verifyer verifyer = BCrypt.verifyer();

        String pw = "a90üdjanlasdn_asdlk";
        byte[] salt = Bytes.random(16).array();
        byte[] hash1 = bCrypt.hash(6, pw.toCharArray());
        byte[] hash2 = bCrypt.hash(7, salt, pw.getBytes(StandardCharsets.UTF_8));
        char[] hash3 = bCrypt.hashToChar(4, pw.toCharArray());

        assertFalse(Bytes.wrap(hash1).equals(hash2));
        assertTrue(verifyer.verify(pw.toCharArray(), new String(hash1, StandardCharsets.UTF_8).toCharArray()).verified);
        assertTrue(verifyer.verify(pw.getBytes(StandardCharsets.UTF_8), hash2).verified);
        assertTrue(verifyer.verify(pw.toCharArray(), hash3).verified);
    }

    @Test(expected = IllegalArgumentException.class)
    public void createHashCostTooSmall() {
        BCrypt.withDefaults().hash(3, "123".toCharArray());
    }

    @Test(expected = IllegalArgumentException.class)
    public void createHashCostTooBig() {
        BCrypt.withDefaults().hash(32, "123".toCharArray());
    }

    @Test(expected = IllegalArgumentException.class)
    public void createHashWithNullSalt() {
        BCrypt.withDefaults().hash(6, null, "123".getBytes());
    }

    @Test(expected = IllegalArgumentException.class)
    public void createHashWithSaltTooShort() {
        BCrypt.withDefaults().hash(6, new byte[15], "123".getBytes());
    }

    @Test(expected = IllegalArgumentException.class)
    public void createHashWithSaltTooLong() {
        BCrypt.withDefaults().hash(6, new byte[17], "123".getBytes());
    }

    @Test(expected = IllegalArgumentException.class)
    public void createHashWithPwNull() {
        BCrypt.withDefaults().hash(6, new byte[16], null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void createHashWithCharPwNull() {
        BCrypt.withDefaults().hash(6, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void createHashWithPwTooLong() {
        BCrypt.withDefaults().hash(6, new byte[16], new byte[73]);
    }

    @Test
    public void verifyWithResult() {
        BCrypt.Hasher bCrypt = BCrypt.withDefaults();
        byte[] pw = "78PHasdhklöALÖö".getBytes();
        byte[] hash = bCrypt.hash(8, Bytes.random(16).array(), pw);

        BCrypt.Result result = BCrypt.verifyer().verify(pw, hash);
        assertTrue(result.verified);
        assertTrue(result.validFormat);
        assertEquals(BCrypt.Version.VERSION_2A, result.details.version);
        assertEquals(8, result.details.cost);
    }

    @Test
    public void verifyWithResultChars() {
        BCrypt.Hasher bCrypt = BCrypt.withDefaults();
        String pw = "7OHIJAslkjdhö#d";
        char[] hash = bCrypt.hashToChar(6, pw.toCharArray());

        BCrypt.Result result = BCrypt.verifyer().verify(pw.toCharArray(), hash);
        assertTrue(result.verified);
        assertTrue(result.validFormat);
        assertEquals(BCrypt.Version.VERSION_2A, result.details.version);
        assertEquals(6, result.details.cost);
    }

    @Test
    public void verifyIncorrectStrictVersion() {
        BCrypt.Hasher bCrypt = BCrypt.with(BCrypt.Version.VERSION_2Y);
        byte[] pw = "78PHasdhklöALÖö".getBytes();
        byte[] hash = bCrypt.hash(5, Bytes.random(16).array(), pw);

        BCrypt.Result result = BCrypt.verifyer().verifyStrict(pw, hash, BCrypt.Version.VERSION_2A);
        assertFalse(result.verified);
        assertTrue(result.validFormat);
        assertEquals(BCrypt.Version.VERSION_2Y, result.details.version);
        assertEquals(5, result.details.cost);
    }

    @Test
    public void verifyIncorrectStrictVersionChars() {
        BCrypt.Hasher bCrypt = BCrypt.with(BCrypt.Version.VERSION_2X);
        String pw = "8PAsdjhlkjhkjla_ääas#d";
        char[] hash = bCrypt.hashToChar(5, pw.toCharArray());

        BCrypt.Result result = BCrypt.verifyer().verifyStrict(pw.toCharArray(), hash, BCrypt.Version.VERSION_2A);
        assertFalse(result.verified);
        assertTrue(result.validFormat);
        assertEquals(BCrypt.Version.VERSION_2X, result.details.version);
        assertEquals(5, result.details.cost);
    }

    @Test
    public void verifyIncorrectFormat() {
        BCrypt.Result result = BCrypt.verifyer().verify("78PHasdhklöALÖö".getBytes(), "$2a$6$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i".getBytes());
        assertFalse(result.validFormat);
        assertFalse(result.verified);
        assertNotNull(result.formatErrorMessage);
        System.out.println(result.formatErrorMessage);
    }

    @Test
    public void testPartsPojoMethods() {
        BCrypt.Result results1 = new BCrypt.Result(null, true);
        BCrypt.Result results2 = new BCrypt.Result(null, true);
        BCrypt.Result results3 = new BCrypt.Result(new IllegalBCryptFormatException("test"));

        assertEquals(results1, results2);
        assertEquals(results1.hashCode(), results2.hashCode());
        assertNotEquals(results1, results3);
        assertNotEquals(results1.hashCode(), results3.hashCode());
        assertNotEquals(results2, results3);
        assertNotEquals(results2.hashCode(), results3.hashCode());

        assertNotNull(results1.toString());
        assertNotNull(results2.toString());
        assertNotNull(results3.toString());
    }
}
