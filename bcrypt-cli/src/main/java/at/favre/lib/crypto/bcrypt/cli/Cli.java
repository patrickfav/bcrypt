package at.favre.lib.crypto.bcrypt.cli;

import at.favre.lib.crypto.bcrypt.BCrypt;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public final class Cli {
    private Cli() {
    }

    public static void main(String[] args) {
        Arg arguments = CLIParser.parse(args);

        if (arguments != null) {
            execute(arguments);
        }
    }

    private static void execute(Arg arguments) {
        byte[] hash = BCrypt.withDefaults().hash(arguments.costFactor, arguments.salt, charArrayToByteArray(arguments.password, StandardCharsets.UTF_8));
        System.out.println(new String(hash, StandardCharsets.UTF_8));
    }

    private static byte[] charArrayToByteArray(char[] charArray, Charset charset) {
        ByteBuffer bb = charset.encode(CharBuffer.wrap(charArray));
        byte[] bytes = new byte[bb.remaining()];
        bb.get(bytes);
        return bytes;
    }

    static String jarVersion() {
        return Cli.class.getPackage().getImplementationVersion();
    }
}
