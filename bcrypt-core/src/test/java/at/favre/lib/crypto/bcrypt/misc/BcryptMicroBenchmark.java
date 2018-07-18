package at.favre.lib.crypto.bcrypt.misc;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bcrypt.BCrypt;
import org.junit.Ignore;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class BcryptMicroBenchmark {

    private final Random rnd = new Random();
    private final Map<AbstractBcrypt, Long> resultMap = new HashMap<>();

    @Test
    @Ignore
    public void benchmark() {
        int rounds = 300;
        List<AbstractBcrypt> contender = Arrays.asList(new FavreBcrypt(), new JBcrypt(), new BC());

        System.out.println("warmup\n\n");

        warmup(contender);

        sleep(3);

        for (int cost : new int[]{6, 8, 10, 12}) {
            System.out.println("\nstart benchmark with " + rounds + " rounds and cost-factor " + cost + "\n\n");

            for (AbstractBcrypt abstractBcrypt : contender) {
                benchmarkSingle(abstractBcrypt, cost, rounds);
                sleep(2);
            }

            System.out.println("\nresults:\n\n");

            for (Map.Entry<AbstractBcrypt, Long> entry : resultMap.entrySet()) {
                System.out.println(entry.getKey().getClass().getSimpleName() + ": " + entry.getValue() + "ms (" + (Math.round(((double) entry.getValue() / (double) rounds) * 100.0) / 100.0) + " ms/round)");
            }
        }
    }

    private void sleep(int seconds) {
        try {
            Thread.sleep(TimeUnit.SECONDS.toMillis(seconds));
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private void warmup(List<AbstractBcrypt> contender) {
        byte[][] cache = new byte[25][];
        for (int i = 0; i < 100; i++) {
            Collections.shuffle(contender);
            for (AbstractBcrypt abstractBcrypt : contender) {
                byte[] out = abstractBcrypt.bcrypt(rnd.nextInt(3) + 4, Bytes.random(20).array());
                cache[rnd.nextInt(cache.length)] = out;
            }
        }

        for (byte[] bytes : cache) {
            System.out.println(Bytes.wrapNullSafe(bytes).encodeBase64());
        }
    }

    private void benchmarkSingle(AbstractBcrypt contender, int cost, int rounds) {
        byte[][] cache = new byte[10][];

        long start = System.currentTimeMillis();
        for (int i = 0; i < rounds; i++) {
            byte[] out = contender.bcrypt(cost, Bytes.random(20).array());
            cache[rnd.nextInt(cache.length)] = out;
        }

        resultMap.put(contender, System.currentTimeMillis() - start);

        for (byte[] bytes : cache) {
            System.out.println(Bytes.wrapNullSafe(bytes).encodeBase64());
        }
    }


    public static final class FavreBcrypt implements AbstractBcrypt {
        @Override
        public byte[] bcrypt(int cost, byte[] password) {
            return BCrypt.withDefaults().hash(cost, password);
        }
    }

    public static final class JBcrypt implements AbstractBcrypt {
        @Override
        public byte[] bcrypt(int cost, byte[] password) {
            return org.mindrot.jbcrypt.BCrypt.hashpw(new String(password, StandardCharsets.UTF_8), org.mindrot.jbcrypt.BCrypt.gensalt(cost)).getBytes(StandardCharsets.UTF_8);
        }
    }

    public static final class BC implements AbstractBcrypt {
        @Override
        public byte[] bcrypt(int cost, byte[] password) {
            return org.bouncycastle.crypto.generators.BCrypt.generate(Bytes.from(password).append((byte) 0).array(), Bytes.random(16).array(), cost);
        }
    }

    public interface AbstractBcrypt {
        byte[] bcrypt(int cost, byte[] password);
    }
}
