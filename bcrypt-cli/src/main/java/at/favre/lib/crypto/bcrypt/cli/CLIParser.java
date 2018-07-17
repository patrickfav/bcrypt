package at.favre.lib.crypto.bcrypt.cli;

import org.apache.commons.cli.*;

/**
 * Parses the command line input and converts it to a structured model ({@link Arg}
 * <p>
 * bcrypt-cli $password $work_factor
 * <p>
 * usage: bcrypt [-h] [-v] [-s SALT] [-V] [-r ROUNDS] [rawText]
 * <p>
 * debcrypt [-h] [-v] [-Q] hash [rawText]
 * <p>
 * htpasswd -bnBC 10 "" password | tr -d ':\n'
 * -b takes the password from the second command argument
 * -n prints the hash to stdout instead of writing it to a file
 * -B instructs to use bcrypt
 * -C 10 sets the bcrypt cost to 10
 */
public final class CLIParser {

    public static final String ARG_HASH = "h";
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

//            argument.apkFile = commandLine.getOptionValues(ARG_APK_FILE);
//            argument.zipAlignPath = commandLine.getOptionValue("zipAlignPath");
//            argument.out = commandLine.getOptionValue(ARG_APK_OUT);
//
//            if (commandLine.hasOption("ksDebug") && commandLine.hasOption("ks")) {
//                throw new IllegalArgumentException("Either provide normal keystore or debug keystore location, not both.");
//            }
//
//            if (commandLine.hasOption("verifySha256")) {
//                argument.checkCertSha256 = commandLine.getOptionValues("verifySha256");
//            }
//
//            argument.signArgsList = new MultiKeystoreParser().parse(commandLine);
//            argument.ksIsDebug = commandLine.hasOption("ksDebug");
//            argument.onlyVerify = commandLine.hasOption(ARG_VERIFY);
//            argument.dryRun = commandLine.hasOption("dryRun");
//            argument.debug = commandLine.hasOption("debug");
//            argument.overwrite = commandLine.hasOption("overwrite");
//            argument.verbose = commandLine.hasOption("verbose");
//            argument.allowResign = commandLine.hasOption("allowResign");
//            argument.skipZipAlign = commandLine.hasOption(ARG_SKIP_ZIPALIGN);
//
//            if (argument.apkFile == null || argument.apkFile.length == 0) {
//                throw new IllegalArgumentException("must provide apk file or folder");
//            }
//
//            if (argument.overwrite && argument.out != null) {
//                throw new IllegalArgumentException("either provide out path or overwrite argument, cannot process both");
//            }

        } catch (Exception e) {
            System.err.println(e.getMessage());

            CLIParser.printHelp(options);

            argument = null;
        }

        return argument;
    }

    static Options setupOptions() {
        Options options = new Options();
        Option optHash = Option.builder(ARG_HASH).longOpt("hash").argName("cost [salt-bytes-hex]").hasArgs().desc("Use this flag if you want to compute the bcrypt hash. Pass the logarithm cost factor (4-31) and optionally the used salt" +
                " as hex encoded byte array (must be exactly 16 bytes/32 characters hex). Example: '--hash 12 8e270d6129fd45f30a9b3fe44b4a8d9a'").build();
        Option optCheck = Option.builder(ARG_CHECK).longOpt("check").argName("bcrypt-hash").hasArg().desc("Use this flag if you want to verify a hash against a given password. Example: '--check $2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i'").build();

        Option help = Option.builder("h").longOpt("help").desc("Prints help docs.").build();
        Option version = Option.builder("v").longOpt("version").desc("Prints current version.").build();

        OptionGroup mainArgs = new OptionGroup();
        mainArgs.addOption(optHash).addOption(optCheck).addOption(help).addOption(version);
        mainArgs.setRequired(true);

        options.addOptionGroup(mainArgs);
        return options;
    }

    private static void printHelp(Options options) {
        HelpFormatter help = new HelpFormatter();
        help.setWidth(110);
        help.setLeftPadding(4);
        help.printHelp("bcrypt", "Version: " + Cli.jarVersion(), options, "", true);
    }
}
