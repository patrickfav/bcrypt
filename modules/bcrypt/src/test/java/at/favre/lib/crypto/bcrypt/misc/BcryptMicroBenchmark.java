package at.favre.lib.crypto.bcrypt.misc;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bcrypt.BCrypt;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

public class BcryptMicroBenchmark {

    private final Random rnd = new Random();
    private Map<AbstractBcrypt, Map<Integer, Long>> map;
    private final int roundsFactor;
    private final int[] costFactorsTotest;
    private final int waitSec;
    private final boolean skipWarmup;

    public BcryptMicroBenchmark(int roundsFactor, int[] costFactorsTotest, int waitSec, boolean skipWarmup) {
        this.roundsFactor = roundsFactor;
        this.costFactorsTotest = costFactorsTotest;
        this.waitSec = waitSec;
        this.skipWarmup = skipWarmup;
    }

    public void benchmark() {
        List<AbstractBcrypt> contender = Arrays.asList(new FavreBcrypt(), new JBcrypt(), new BC());
        prepareMap(contender);

        if (!skipWarmup) {
            System.out.println("warmup\n");

            warmup(contender);

            sleep(waitSec * 2);
        }

        for (int cost : costFactorsTotest) {
            int currentRounds = calculateRounds(roundsFactor, cost);
            System.out.println("\n\nbenchmark with " + currentRounds + " rounds and cost-factor " + cost + "\n");

            for (AbstractBcrypt abstractBcrypt : contender) {
                benchmarkSingle(abstractBcrypt, cost, currentRounds);
                sleep(waitSec);
            }
        }

        System.out.println("\n\nResults:");
        System.out.println("\t" + System.getProperty("os.arch") + ", Java " + System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + "), " + System.getProperty("os.name") + " (" + System.getProperty("os.version") + ")\n\n");

        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (Map.Entry<AbstractBcrypt, Map<Integer, Long>> entry : map.entrySet()) {

            if (count == 0) {
                sb.append("|              |");
                for (Integer cost : entry.getValue().keySet()) {
                    sb.append("  cost ").append(String.format("%-2s", cost)).append("     |");
                }
                sb.append("\n");

                for (int i = 0; i < entry.getValue().keySet().size() + 1; i++) {
                    sb.append("| ------------ ");
                }
                sb.append("|\n");
            }


            sb.append("| ").append(String.format("%-12s", entry.getKey().getClass().getSimpleName())).append(" |");
            for (Map.Entry<Integer, Long> iEntry : entry.getValue().entrySet()) {
                sb.append(String.format("  %-8s", Math.round(((double) iEntry.getValue() / (double) calculateRounds(roundsFactor, iEntry.getKey())) * 100.0) / 100.0)).append(" ms |");
            }
            sb.append("\n");
            count++;
        }

        System.out.println(sb.toString());
    }

    private int calculateRounds(int rounds, int cost) {
        return Math.max(4, Math.min(250, rounds / (1 << cost)));
    }

    private void prepareMap(List<AbstractBcrypt> contender) {
        map = new HashMap<>();
        for (AbstractBcrypt abstractBcrypt : contender) {
            map.put(abstractBcrypt, new TreeMap<Integer, Long>());
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
            System.out.print(Bytes.wrapNullSafe(bytes).encodeBase64());
        }
    }

    private void benchmarkSingle(AbstractBcrypt contender, int cost, int rounds) {
        byte[][] cache = new byte[10][];

        long start = System.currentTimeMillis();
        for (int i = 0; i < rounds; i++) {
            byte[] out = contender.bcrypt(cost, Bytes.random(20).array());
            cache[rnd.nextInt(cache.length)] = out;
        }

        map.get(contender).put(cost, System.currentTimeMillis() - start);

        for (byte[] bytes : cache) {
            System.out.print(Bytes.wrapNullSafe(bytes).encodeBase64());
        }
    }


    static final class FavreBcrypt implements AbstractBcrypt {
        @Override
        public byte[] bcrypt(int cost, byte[] password) {
            return BCrypt.withDefaults().hash(cost, password);
        }
    }

    static final class JBcrypt implements AbstractBcrypt {
        @Override
        public byte[] bcrypt(int cost, byte[] password) {
            return org.mindrot.jbcrypt.BCrypt.hashpw(new String(password, StandardCharsets.UTF_8), org.mindrot.jbcrypt.BCrypt.gensalt(cost)).getBytes(StandardCharsets.UTF_8);
        }
    }

    static final class BC implements AbstractBcrypt {
        @Override
        public byte[] bcrypt(int cost, byte[] password) {
            return org.bouncycastle.crypto.generators.BCrypt.generate(Bytes.from(password).append((byte) 0).array(), Bytes.random(16).array(), cost);
        }
    }

    interface AbstractBcrypt {
        byte[] bcrypt(int cost, byte[] password);
    }
}
