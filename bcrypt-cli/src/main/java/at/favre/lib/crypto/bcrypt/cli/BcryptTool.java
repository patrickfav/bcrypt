package at.favre.lib.crypto.bcrypt.cli;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bcrypt.BCrypt;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * A simple cli tool that can hash and verify bcrypt hashes
 */
public final class BcryptTool {
    private BcryptTool() {
    }

    /**
     * Will exit with
     * <p>
     * 0 - everything ok (verified)
     * 1 - could not verify hash
     * 2 - error while parsing cli arguments
     * 3 - invalid bcrypt hash while verifying
     * 4 - general error
     *
     * @param args
     */
    public static void main(String[] args) {
        System.exit(execute(CLIParser.parse(args), System.out, System.err));
    }

    /**
     * Execute the given arguments and executes the appropriate actions
     *
     * @param arguments
     * @param stream
     * @param errorStream
     * @return the exit code of the tool
     */
    static int execute(Arg arguments, PrintStream stream, PrintStream errorStream) {
        if (arguments == null) {
            return 2;
        }

        if (arguments.checkBcryptHash != null) { // verify mode
            BCrypt.Result result = BCrypt.verifyer().verify(arguments.password, arguments.checkBcryptHash);
            if (!result.validFormat) {
                System.err.println("Invalid bcrypt format.");
                return 3;
            }

            if (result.verified) {
                stream.println("Hash verified.");
            } else {
                errorStream.println("Provided hash does not verify against given password.");
                return 1;
            }
        } else { // hash mode
            byte[] salt = arguments.salt == null ? Bytes.random(16).array() : arguments.salt;
            byte[] hash = BCrypt.withDefaults().hash(arguments.costFactor, salt, charArrayToByteArray(arguments.password, StandardCharsets.UTF_8));
            stream.println(new String(hash, StandardCharsets.UTF_8));
        }
        return 0;
    }

    private static byte[] charArrayToByteArray(char[] charArray, Charset charset) {
        ByteBuffer bb = charset.encode(CharBuffer.wrap(charArray));
        byte[] bytes = new byte[bb.remaining()];
        bb.get(bytes);
        return bytes;
    }

    static String jarVersion() {
        return BcryptTool.class.getPackage().getImplementationVersion();
    }
}
