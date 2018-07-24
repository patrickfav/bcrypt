package at.favre.lib.crypto.bcrypt;

import org.junit.Rule;
import org.junit.Test;
import org.junit.internal.runners.statements.FailOnTimeout;
import org.junit.rules.Timeout;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.junit.runners.model.TestTimedOutException;

import java.util.concurrent.TimeoutException;

public class BCryptHighCostTest {

    private final char[] password = "1234567890abcdefABCDEF_.,".toCharArray();

    private static final int MIN_TIMEOUT = 100;

    @Rule
    public Timeout timeout = new Timeout(MIN_TIMEOUT) {
        public Statement apply(Statement base, Description description) {
            return new FailOnTimeout(base, MIN_TIMEOUT) {
                @Override
                public void evaluate() throws Throwable {
                    try {
                        super.evaluate();
                        throw new TimeoutException();
                    } catch (Exception e) {
                    }
                }
            };
        }
    };

    @Test(expected = TestTimedOutException.class)
    public void testHashWithMaxCostFactorAndTimeout() {
        BCrypt.withDefaults().hash(31, password);
    }

    @Test(expected = TestTimedOutException.class)
    public void testHashWith30CostFactorAndTimeout() {
        BCrypt.withDefaults().hash(30, password);
    }

    @Test(expected = TestTimedOutException.class)
    public void testHashWith29CostFactorAndTimeout() {
        BCrypt.withDefaults().hash(29, password);
    }

    @Test(expected = TestTimedOutException.class)
    public void testHashWith28CostFactorAndTimeout() {
        BCrypt.withDefaults().hash(28, password);
    }

    @Test(expected = TestTimedOutException.class)
    public void testHashWith27CostFactorAndTimeout() {
        BCrypt.withDefaults().hash(27, password);
    }

    @Test(expected = TestTimedOutException.class)
    public void testHashWith26CostFactorAndTimeout() {
        BCrypt.withDefaults().hash(26, password);
    }

    @Test(expected = TestTimedOutException.class)
    public void testHashWith25CostFactorAndTimeout() {
        BCrypt.withDefaults().hash(25, password);
    }

    @Test(expected = TestTimedOutException.class)
    public void testHashWith24CostFactorAndTimeout() {
        BCrypt.withDefaults().hash(24, password);
    }
}
