package at.favre.lib.crypto.bcrypt.misc;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.Radix64Encoder;
import com.github.fzakaria.ascii85.Ascii85;
import org.apache.commons.text.StringEscapeUtils;

import java.nio.charset.StandardCharsets;

public class BcryptTestEntriesGenerator {

    private final int pwLengthByte;
    private final int[] costFactors;
    private final int examplesPerCostFactor;
    private final BCrypt.Version version;
    private final boolean sameSaltAllExamples;
    private final boolean samePasswordAllExamples;

    public BcryptTestEntriesGenerator(int pwLengthByte, int[] costFactors, int examplesPerCostFactor, BCrypt.Version version, boolean sameSaltAllExamples, boolean samePasswordAllExamples) {
        this.pwLengthByte = pwLengthByte;
        this.costFactors = costFactors;
        this.examplesPerCostFactor = examplesPerCostFactor;
        this.version = version;
        this.sameSaltAllExamples = sameSaltAllExamples;
        this.samePasswordAllExamples = samePasswordAllExamples;
    }

    public void printRefData() {
        StringBuilder sb = new StringBuilder("new BcryptTestEntry[] {\n");
        byte[] salt = generateSalt();
        String pw = generatePw();

        Radix64Encoder encoder = new Radix64Encoder.Default();
        for (int costFactor : costFactors) {
            for (int i = 0; i < examplesPerCostFactor; i++) {
                if (!sameSaltAllExamples) {
                    salt = generateSalt();
                }
                if (!samePasswordAllExamples) {
                    pw = generatePw();
                }
                BCrypt.HashData data = BCrypt.with(version).hashRaw(costFactor, salt, Bytes.from(pw).array());

                sb.append("new BcryptTestEntry(\"")
                        .append(StringEscapeUtils.escapeJava(pw))
                        .append("\", ")
                        .append(costFactor).append(", ")
                        .append("\"")
                        .append(new String(encoder.encode(salt), StandardCharsets.UTF_8)).append("\", \"")
                        .append(new String(version.formatter.createHashMessage(data), StandardCharsets.UTF_8)).append("\"), \n");
            }
        }
        sb.append("}");

        System.out.println(sb.toString());
    }

    private String generatePw() {
        return Ascii85.encode(Bytes.random(pwLengthByte).array());
    }

    private byte[] generateSalt() {
        return Bytes.random(16).array();
    }
}
