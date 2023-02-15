package at.favre.lib.crypto.bcrypt.cli;

import at.favre.lib.bytes.Bytes;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;

/**
 * Parses the command line input and converts it to a structured model ({@link Arg}
 */
public final class CLIParser {

    public static final String ARG_HASH = "b";
    public static final String ARG_CHECK = "c";

    private CLIParser() {
    }

    public static Arg parse(String[] inputArgs) {
        Options options = setupOptions();
        CommandLineParser parser = new DefaultParser();
        Arg argument = new Arg();

        try {
            CommandLine commandLine = parser.parse(options, inputArgs);

            if (commandLine.hasOption("h") || commandLine.hasOption("help")) {
                printHelp(options);
                return null;
            }

            if (commandLine.hasOption("v") || commandLine.hasOption("version")) {
                System.out.println("Version: " + CLIParser.class.getPackage().getImplementationVersion());
                return null;
            }

            if (commandLine.getArgs().length == 0) {
                throw new IllegalArgumentException("First parameter must be password (e.g. bcrypt 'mysecretpassword' -" + ARG_HASH + " 12)");
            }

            char[] password = commandLine.getArgs()[0].toCharArray();

            if (commandLine.hasOption(ARG_HASH)) {

                return handleHash(commandLine, password);
            } else if (commandLine.hasOption(ARG_CHECK)) {
                return handleCheck(commandLine, password);
            }
        } catch (Exception e) {
            String msg = e.getMessage();
            System.err.println(msg.length() > 80 ? msg.substring(0, 80) + "..." : msg);

            CLIParser.printHelp(options);

            argument = null;
        }

        return argument;
    }

    private static Arg handleHash(CommandLine commandLine, char[] password) {
        String[] hashParams = commandLine.getOptionValues(ARG_HASH);

        if (hashParams == null || hashParams.length == 0) {
            throw new IllegalArgumentException("Hash mode expects at least the cost parameter. (e.g.  '-" + ARG_HASH + " 12')");
        }

        final int costFactor;
        try {
            costFactor = Integer.parseInt(hashParams[0]);
        } catch (Exception e) {
            throw new IllegalArgumentException("First parameter of hash expected to be integer type, was " + hashParams[0]);
        }

        byte[] salt = null;
        if (hashParams.length > 1) {
            try {
                salt = Bytes.parseHex(hashParams[1]).array();
            } catch (Exception e) {
                throw new IllegalArgumentException("Salt parameter could not be parsed as hex [0-9a-f], was " + hashParams[1]);
            }

            if (salt.length != 16) {
                throw new IllegalArgumentException("Salt parameter must be exactly 16 bytes (32 characters hex)");
            }
        }
        return new Arg(password, salt, costFactor);
    }

    private static Arg handleCheck(CommandLine commandLine, char[] password) {
        String refBcrypt = commandLine.getOptionValue(ARG_CHECK);

        if (refBcrypt == null || refBcrypt.trim().length() != 60) {
            throw new IllegalArgumentException("Reference bcrypt hash must be exactly 60 characters, e.g. '$2a$10$6XBbrUraPyfq7nxeaYsR4u.3.ZuGNCy3tOT4reneAI/qoWvP6AX/e' was " + refBcrypt);
        }

        return new Arg(password, refBcrypt);
    }

    static Options setupOptions() {
        Options options = new Options();
        Option optHash = Option.builder(ARG_HASH).longOpt("bhash").argName("cost> <[16-hex-byte-salt]").hasArgs().desc("Use this flag if you want to compute the bcrypt hash. Pass the logarithm cost factor (4-31) and optionally the used salt" +
                " as hex encoded byte array (must be exactly 16 bytes/32 characters hex). Example: '--bhash 12 8e270d6129fd45f30a9b3fe44b4a8d9a'").required().build();
        Option optCheck = Option.builder(ARG_CHECK).longOpt("check").argName("bcrypt-hash").hasArg().desc("Use this flag if you want to verify a hash against a given password. Example: '--check $2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i'").build();

        Option help = Option.builder("h").longOpt("help").desc("Prints help docs.").build();
        Option version = Option.builder("v").longOpt("version").desc("Prints current version.").build();

        OptionGroup mainArgs = new OptionGroup();
        mainArgs.addOption(optCheck).addOption(optHash).addOption(help).addOption(version);
        mainArgs.setRequired(true);

        options.addOptionGroup(mainArgs);
        return options;
    }

    private static void printHelp(Options options) {
        HelpFormatter help = new HelpFormatter();
        help.setWidth(110);
        help.setLeftPadding(4);
        help.printHelp("bcrypt <password>", "Version: " + BcryptTool.jarVersion(), options, "", true);
    }
}
