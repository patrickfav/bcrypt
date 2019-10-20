package at.favre.lib.crypto.bcrypt.cli;

import at.favre.lib.bytes.Bytes;
import org.apache.tools.ant.types.Commandline;
import org.junit.Test;

import java.util.Random;

import static junit.framework.TestCase.assertNotNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class CLIParserTest {
    private final String defaultPw = "secretPw1234_äöü+~";
    private final String defaultCheckBcrypt = "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i";

    @Test
    public void testWithDoubleDigitCostFactor() {
        Arg parsedArg = CLIParser.parse(asArgArray("'" + defaultPw + "' -" + CLIParser.ARG_HASH + " 12"));
        Arg expectedArg = new Arg(defaultPw.toCharArray(), null, 12);
        assertEquals(expectedArg, parsedArg);
    }

    @Test
    public void testDifferentPasswordsAndCostFactors() {
        for (int i = 0; i < 1000; i++) {
            int costFactor = new Random().nextInt(24) + 4;
            String pw = Bytes.random(new Random().nextInt(30) + 2).encodeBase64();
            Arg parsedArg = CLIParser.parse(asArgArray("'" + pw + "' -" + CLIParser.ARG_HASH + " " + costFactor));
            Arg expectedArg = new Arg(pw.toCharArray(), null, costFactor);
            assertEquals(expectedArg, parsedArg);
        }
    }


    @Test
    public void testWithSingleDigitCostFactor() {
        Arg parsedArg = CLIParser.parse(asArgArray("'" + defaultPw + "' -" + CLIParser.ARG_HASH + " 6"));
        Arg expectedArg = new Arg(defaultPw.toCharArray(), null, 6);
        assertEquals(expectedArg, parsedArg);
    }

    @Test
    public void testWithSingleDigitCostFactor2() {
        Arg parsedArg = CLIParser.parse(asArgArray("'" + defaultPw + "' -" + CLIParser.ARG_HASH + " 04"));
        Arg expectedArg = new Arg(defaultPw.toCharArray(), null, 4);
        assertEquals(expectedArg, parsedArg);
    }

    @Test
    public void testWithoutCostFactorShouldReturnNull() {
        assertNull(CLIParser.parse(asArgArray("'" + defaultPw + "' -" + CLIParser.ARG_HASH)));
    }

    @Test
    public void testWithDoubleDigitCostFactorAndSalt() {
        String salt = "490d9611ab0930a9d9ef87768553366f";
        Arg parsedArg = CLIParser.parse(asArgArray("'" + defaultPw + "' -" + CLIParser.ARG_HASH + " 11 '" + salt + "'"));
        Arg expectedArg = new Arg(defaultPw.toCharArray(), Bytes.parseHex(salt).array(), 11);
        assertEquals(expectedArg, parsedArg);
    }

    @Test
    public void testWithSaltWrongLengthReturnNull() {
        assertNull(CLIParser.parse(asArgArray("'" + defaultPw + "' -" + CLIParser.ARG_HASH + " 4 490d9611ab0930a9d9ef8776855336")));
        assertNull(CLIParser.parse(asArgArray("'" + defaultPw + "' -" + CLIParser.ARG_HASH + " 6 490d9611ab0930a9d9ef87768553366fe2")));
        assertNull(CLIParser.parse(asArgArray("'" + defaultPw + "' -" + CLIParser.ARG_HASH + " 7 490d9611ab0930a9d9ef87768553366fe")));
    }

    @Test
    public void testWith31LengthSalt_shouldParseWillAppendLeadingZero() {
        assertNotNull(CLIParser.parse(asArgArray("'" + defaultPw + "' -" + CLIParser.ARG_HASH + " 5 490d9611ab0930a9d9ef87768553366")));
    }

    @Test
    public void testWithSaltWrongCharReturnNull() {
        assertNull(CLIParser.parse(asArgArray("'" + defaultPw + "' -" + CLIParser.ARG_HASH + " 4 490d9611ab0930a9d9ef87768553366x")));
    }

    @Test
    public void testWithoutCostFactorButSaltShouldReturnNull() {
        assertNull(CLIParser.parse(asArgArray("'" + defaultPw + "' -" + CLIParser.ARG_HASH + " 490d9611ab0930a9d9ef87768553366f")));
        assertNull(CLIParser.parse(asArgArray("'" + defaultPw + "' -" + CLIParser.ARG_HASH + "490d9611ab0930a9d9ef87768553366f 12")));
    }

    @Test
    public void testCheckShouldWork() {
        Arg parsedArg = CLIParser.parse(asArgArray("'" + defaultPw + "' -" + CLIParser.ARG_CHECK + "'" + defaultCheckBcrypt + "'"));
        Arg expectedArg = new Arg(defaultPw.toCharArray(), defaultCheckBcrypt);
        assertEquals(expectedArg, parsedArg);
    }

    @Test
    public void testCheckTooShortBcrypt() {
        assertNull(CLIParser.parse(asArgArray("'" + defaultPw + "' -" + CLIParser.ARG_CHECK + "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0")));
    }

    @Test
    public void testCheckTooLongBcrypt() {
        assertNull(CLIParser.parse(asArgArray("'" + defaultPw + "' -" + CLIParser.ARG_CHECK + " " + defaultCheckBcrypt + "A")));
    }

    @Test
    public void testHelp() {
        Arg parsedArg = CLIParser.parse(asArgArray("--help"));
        assertNull(parsedArg);
    }

    @Test
    public void testVersion() {
        Arg parsedArg = CLIParser.parse(asArgArray("--version"));
        assertNull(parsedArg);
    }

    public static String[] asArgArray(String cmd) {
        return Commandline.translateCommandline(cmd);
    }

}
