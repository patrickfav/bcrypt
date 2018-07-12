package at.favre.lib.crypto.bcrypt;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.bytes.BytesTransformer;
import org.junit.Test;

import static org.junit.Assert.*;

public class LongPasswordStrategyTest {

    private final int maxLength = 72;

    @Test
    public void testFactory() {
        assertNotNull(LongPasswordStrategies.hashSha512().derive(Bytes.random(100).array()));
        assertNotNull(LongPasswordStrategies.truncate().derive(Bytes.random(100).array()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFactoryForStrictShouldThrowException() {
        LongPasswordStrategies.strict().derive(Bytes.random(100).array());
    }

    @Test
    public void testStrictLengthStrategy() {
        LongPasswordStrategy strategy = new LongPasswordStrategy.StrictMaxPasswordLengthStrategy(maxLength);
        byte[] byteArray;

        for (int i = 1; i < maxLength; i++) {
            byteArray = Bytes.random(i).array();
            assertSame(byteArray, strategy.derive(byteArray));
        }

        checkExpectToFail(maxLength, strategy);

        for (int i = 1; i < maxLength; i++) {
            checkExpectToFail(maxLength + i, strategy);
        }
    }

    private void checkExpectToFail(int maxLength, LongPasswordStrategy strategy) {
        byte[] byteArray;
        try {
            byteArray = Bytes.random(maxLength).array();
            assertArrayEquals(byteArray, strategy.derive(byteArray));
            fail();
        } catch (IllegalArgumentException e) {
        } catch (Exception e) {
            fail();
        }
    }

    @Test
    public void testTruncateStrategy() {
        LongPasswordStrategy strategy = new LongPasswordStrategy.TruncateStrategy(maxLength);
        byte[] byteArray;

        for (int i = 1; i < maxLength; i++) {
            byteArray = Bytes.random(i).array();
            assertSame(byteArray, strategy.derive(byteArray));
        }

        testTooLongTruncate(maxLength, maxLength, strategy);

        for (int i = 1; i < maxLength; i++) {
            testTooLongTruncate(maxLength + i, maxLength, strategy);
        }
    }

    private void testTooLongTruncate(int length, int maxLength, LongPasswordStrategy strategy) {
        byte[] byteArray;
        byteArray = Bytes.random(length).array();
        byte[] out = strategy.derive(byteArray);
        assertEquals(maxLength, out.length);
        assertArrayEquals(Bytes.wrap(byteArray).resize(maxLength, BytesTransformer.ResizeTransformer.Mode.RESIZE_KEEP_FROM_ZERO_INDEX).array(), out);
    }

    @Test
    public void testSha512HashStrategy() {
        LongPasswordStrategy strategy = new LongPasswordStrategy.Sha512DerivationStrategy(maxLength);
        byte[] byteArray;

        for (int i = 1; i < maxLength; i++) {
            byteArray = Bytes.random(i).array();
            assertSame(byteArray, strategy.derive(byteArray));
        }

        for (int i = maxLength; i < maxLength * 2; i++) {
            byteArray = Bytes.random(maxLength).array();
            assertArrayEquals(Bytes.wrap(byteArray).hash("SHA-512").array(), strategy.derive(byteArray));
            assertTrue(byteArray.length <= maxLength);
            System.out.println(Bytes.wrap(byteArray).encodeHex());
        }
    }
}
