package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.bytes.BytesTransformer;
import at.favre.lib.crypto.bcrypt.misc.Repeat;
import at.favre.lib.crypto.bcrypt.misc.RepeatRule;
import org.junit.Rule;
import org.junit.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Random;

import static at.favre.lib.crypto.bcrypt.BCrypt.MAJOR_VERSION;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

public class BcryptTest {
    @Rule
    public RepeatRule repeatRule = new RepeatRule();
    public static final Charset UTF_8 = StandardCharsets.UTF_8;

    private BcryptTestEntry[] testEntries = new BcryptTestEntry[]{
            // see: https://stackoverflow.com/a/12761326/774398
            new BcryptTestEntry("ππππππππ", 10, ".TtQJ4Jr6isd4Hp.mVfZeu", "$2a$10$.TtQJ4Jr6isd4Hp.mVfZeuh6Gws4rOQ/vdBczhDx.19NFK0Y84Dle"),
            // see: http://openwall.info/wiki/john/sample-hashes
            new BcryptTestEntry("password", 5, "bvIG6Nmid91Mu9RcmmWZfO", "$2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe"),
            // see: http://cvsweb.openwall.com/cgi/cvsweb.cgi/Owl/packages/glibc/crypt_blowfish/wrapper.c?rev=HEAD
            new BcryptTestEntry("U*U", 5, "CCCCCCCCCCCCCCCCCCCCC.", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"),
            new BcryptTestEntry("U*U*", 5, "CCCCCCCCCCCCCCCCCCCCC.", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"),
            new BcryptTestEntry("U*U*U", 5, "XXXXXXXXXXXXXXXXXXXXXO", "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a")
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
    public void readmeExamples() {
        String password = "1234";
        //Versions
        char[] bcrypt2yChars = BCrypt.with(BCrypt.Version.VERSION_2Y).hashToChar(6, password.toCharArray());
        System.out.println(bcrypt2yChars);
        char[] bcrypt2bChars = BCrypt.with(BCrypt.Version.VERSION_2B).hashToChar(6, password.toCharArray());
        System.out.println(bcrypt2bChars);
        //byte[] vs char[]
        byte[] bcryptHashBytes = BCrypt.withDefaults().hash(6, password.getBytes(StandardCharsets.UTF_8));
        BCrypt.Result result = BCrypt.verifyer().verify(password.getBytes(StandardCharsets.UTF_8), bcryptHashBytes);
        //verify strict
        byte[] hash2y = BCrypt.with(BCrypt.Version.VERSION_2Y).hash(6, password.getBytes(StandardCharsets.UTF_8));
        BCrypt.Result resultStrict = BCrypt.verifyer().verifyStrict(password.getBytes(StandardCharsets.UTF_8), hash2y, BCrypt.Version.VERSION_2A);
        //overlong passwords
        BCrypt.with(LongPasswordStrategies.truncate()).hash(6, new byte[100]);
        BCrypt.with(LongPasswordStrategies.hashSha512()).hash(6, new byte[100]);
        //custom salt and secure random
        BCrypt.withDefaults().hash(6, Bytes.random(16).array(), password.getBytes(StandardCharsets.UTF_8));
        BCrypt.with(new SecureRandom()).hash(6, password.getBytes(StandardCharsets.UTF_8));
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
    public void testHashAllVersions() throws Exception {
        for (BCrypt.Version version : BCrypt.Version.SUPPORTED_VERSIONS) {
            checkHash(BCrypt.with(version));
        }
    }

    @Test
    public void testSecureRandom() throws Exception {
        checkHash(BCrypt.with(new SecureRandom()));
    }

    @Test
    public void testLongPasswordStrategy() throws Exception {
        checkHash(BCrypt.with(new LongPasswordStrategy.TruncateStrategy(BCrypt.MAX_PW_LENGTH_BYTE)));
    }

    @Test
    public void testFullyCustom() throws Exception {
        checkHash(BCrypt.with(BCrypt.Version.VERSION_2Y, new SecureRandom(), new LongPasswordStrategy.TruncateStrategy(BCrypt.MAX_PW_LENGTH_BYTE)));
    }

    private void checkHash(BCrypt.Hasher bCrypt) throws Exception {
        BCrypt.Verifyer verifyer = BCrypt.verifyer();

        String pw = "a90üdjanlasdn_asdlk";
        byte[] salt = Bytes.random(16).array();
        byte[] hash1 = bCrypt.hash(6, pw.toCharArray());
        byte[] hash2 = bCrypt.hash(7, salt, pw.getBytes(UTF_8));
        BCrypt.HashData hashData = bCrypt.hashRaw(7, salt, pw.getBytes(UTF_8));
        char[] hash3 = bCrypt.hashToChar(4, pw.toCharArray());

        assertFalse(Bytes.wrap(hash1).equals(hash2));
        assertTrue(verifyer.verify(pw.toCharArray(), new String(hash1, UTF_8).toCharArray()).verified);
        assertTrue(verifyer.verify(pw.getBytes(UTF_8), hash2).verified);
        assertTrue(verifyer.verify(pw.toCharArray(), hash3).verified);
        assertEquals(new BCryptParser.Default(new Radix64Encoder.Default(), UTF_8).parse(hash2), hashData);
    }

    @Test
    @Repeat(20)
    public void hashRandomByteArrays() {
        byte[] pw = Bytes.random(new Random().nextInt(68) + 2).array();
        byte[] hash = BCrypt.withDefaults().hash(4, pw);
        assertTrue(BCrypt.verifyer().verify(pw, hash).verified);
        System.out.println(Bytes.wrap(hash).encodeUtf8());
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
        BCrypt.withDefaults().hash(6, (char[]) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void createHashWithPwTooLong() {
        BCrypt.withDefaults().hash(6, new byte[16], new byte[BCrypt.MAX_PW_LENGTH_BYTE + 1]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void createHashWithPwTooLong2() {
        BCrypt.withDefaults().hash(6, new byte[16], new byte[BCrypt.MAX_PW_LENGTH_BYTE + 2]);
    }

    @Test
    public void testLongPassword() {
        byte[] pw = Bytes.random(BCrypt.MAX_PW_LENGTH_BYTE).array();
        byte[] bcryptHashBytes = BCrypt.withDefaults().hash(4, pw);
        assertTrue(BCrypt.verifyer().verify(pw, bcryptHashBytes).verified);
    }

    @Test
    public void testLongTruncatedPassword() {
        byte[] pw = Bytes.random(BCrypt.MAX_PW_LENGTH_BYTE + 2).array();
        byte[] salt = Bytes.random(16).array();
        byte[] bcryptHashBytes1a = BCrypt.with(LongPasswordStrategies.truncate()).hash(4, salt, pw);
        byte[] bcryptHashBytes1b = BCrypt.with(LongPasswordStrategies.truncate()).hash(4, salt, Bytes.wrap(pw).resize(BCrypt.MAX_PW_LENGTH_BYTE + 1, BytesTransformer.ResizeTransformer.Mode.RESIZE_KEEP_FROM_ZERO_INDEX).array());
        byte[] bcryptHashBytes2 = BCrypt.withDefaults().hash(4, salt, Bytes.wrap(pw).resize(BCrypt.MAX_PW_LENGTH_BYTE, BytesTransformer.ResizeTransformer.Mode.RESIZE_KEEP_FROM_ZERO_INDEX).array());

        assertArrayEquals(bcryptHashBytes1a, bcryptHashBytes1b);
        assertArrayEquals(bcryptHashBytes1a, bcryptHashBytes2);
    }

    @Test
    public void testLongHashedPassword() {
        byte[] pw = Bytes.random(BCrypt.MAX_PW_LENGTH_BYTE + 2).array();
        byte[] salt = Bytes.random(16).array();
        byte[] bcryptHashBytes1 = BCrypt.with(LongPasswordStrategies.hashSha512()).hash(4, salt, pw);
        byte[] bcryptHashBytes2 = BCrypt.with(LongPasswordStrategies.hashSha512()).hash(4, salt, Bytes.wrap(pw).resize(BCrypt.MAX_PW_LENGTH_BYTE + 1, BytesTransformer.ResizeTransformer.Mode.RESIZE_KEEP_FROM_ZERO_INDEX).array());
        assertFalse(Bytes.wrap(bcryptHashBytes1).equals(bcryptHashBytes2));
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
    public void verifyRawByteArrays() {
        BCrypt.Hasher bCrypt = BCrypt.withDefaults();
        byte[] pw = Bytes.random(24).encodeBase36().getBytes();
        BCrypt.HashData hash = bCrypt.hashRaw(6, Bytes.random(16).array(), pw);

        BCrypt.Result result = BCrypt.verifyer().verify(pw, hash);
        assertTrue(result.verified);
        assertTrue(result.validFormat);
        assertEquals(BCrypt.Version.VERSION_2A, result.details.version);
        assertEquals(6, result.details.cost);
    }

    @Test
    public void verifyRawByteArrays2() {
        BCrypt.Hasher bCrypt = BCrypt.withDefaults();
        byte[] pw = Bytes.random(24).encodeBase36().getBytes();
        BCrypt.HashData hash = bCrypt.hashRaw(7, Bytes.random(16).array(), pw);

        BCrypt.Result result = BCrypt.verifyer().verify(pw, hash.cost, hash.rawSalt, hash.rawHash);
        assertTrue(result.verified);
        assertTrue(result.validFormat);
        assertEquals(BCrypt.Version.VERSION_2A, result.details.version);
        assertEquals(7, result.details.cost);
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
    public void testResultPojoMethods() {
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

    @Test
    public void testHashDataPojoMethods() {
        BCrypt.HashData hd1 = new BCrypt.HashData(6, BCrypt.Version.VERSION_2A, new byte[16], new byte[23]);
        BCrypt.HashData hd2 = new BCrypt.HashData(6, BCrypt.Version.VERSION_2A, new byte[16], new byte[23]);
        BCrypt.HashData hd3 = new BCrypt.HashData(7, BCrypt.Version.VERSION_2A, new byte[16], new byte[23]);

        assertEquals(hd1, hd2);
        assertEquals(hd1.hashCode(), hd2.hashCode());
        assertNotEquals(hd1, hd3);
        assertNotEquals(hd1.hashCode(), hd3.hashCode());
        assertNotEquals(hd2, hd3);
        assertNotEquals(hd2.hashCode(), hd3.hashCode());

        assertNotNull(hd1.toString());
        assertNotNull(hd2.toString());
        assertNotNull(hd3.toString());
    }

    @Test
    public void testHashDataWipe() {
        Bytes salt = Bytes.random(16);
        Bytes hash = Bytes.random(23);
        BCrypt.HashData hashData = new BCrypt.HashData(6, BCrypt.Version.VERSION_2A, salt.copy().array(), hash.copy().array());

        assertTrue(hash.equals(hashData.rawHash));
        assertTrue(salt.equals(hashData.rawSalt));

        hashData.wipe();

        assertFalse(hash.equals(hashData.rawHash));
        assertFalse(salt.equals(hashData.rawSalt));
    }

    @Test
    public void testVersionPojoMethods() {
        assertEquals(BCrypt.Version.VERSION_2A, BCrypt.Version.VERSION_2A);
        assertEquals(BCrypt.Version.VERSION_2A, new BCrypt.Version(new byte[]{MAJOR_VERSION, 0x61}, null));
        assertEquals(BCrypt.Version.VERSION_2Y, new BCrypt.Version(new byte[]{MAJOR_VERSION, 0x79}, null));
        assertNotEquals(BCrypt.Version.VERSION_2Y, BCrypt.Version.VERSION_2A);
        assertNotEquals(BCrypt.Version.VERSION_2A, BCrypt.Version.VERSION_2B);
        assertNotEquals(BCrypt.Version.VERSION_2X, BCrypt.Version.VERSION_2Y);

        assertEquals(BCrypt.Version.VERSION_2A.hashCode(), BCrypt.Version.VERSION_2A.hashCode());
        assertEquals(BCrypt.Version.VERSION_2A.hashCode(), new BCrypt.Version(new byte[]{MAJOR_VERSION, 0x61}, null).hashCode());

        assertNotEquals(BCrypt.Version.VERSION_2Y.hashCode(), BCrypt.Version.VERSION_2A.hashCode());
        assertNotEquals(BCrypt.Version.VERSION_2A.hashCode(), BCrypt.Version.VERSION_2B.hashCode());
        assertNotEquals(BCrypt.Version.VERSION_2X.hashCode(), BCrypt.Version.VERSION_2Y.hashCode());
    }
}
