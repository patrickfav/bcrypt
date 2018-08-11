package at.favre.lib.crypto.bcrypt;

import at.favre.lib.crypto.bcrypt.misc.BcryptMicroBenchmark;
import org.junit.Ignore;
import org.junit.Test;

public class BenchmarkTest {

    @Test
    public void quickBenchmark() {
        new BcryptMicroBenchmark(1500, new int[]{4, 5, 6, 7}, 0, true).benchmark();
    }

    @Test
    @Ignore
    public void fullBenchmark() {
        new BcryptMicroBenchmark(819200, new int[]{4, 6, 8, 9, 10, 11, 12, 14, 15}, 2, false).benchmark();
    }

}
