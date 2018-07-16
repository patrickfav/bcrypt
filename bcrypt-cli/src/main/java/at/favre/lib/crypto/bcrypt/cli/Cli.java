package at.favre.lib.crypto.bcrypt.cli;

import at.favre.lib.crypto.bcrypt.BCrypt;

public final class Cli {
    private Cli() {
    }

    public static void main(String[] args) {
        System.out.println(BCrypt.withDefaults().hashToString(4, "asdasd".toCharArray()));
    }
}
