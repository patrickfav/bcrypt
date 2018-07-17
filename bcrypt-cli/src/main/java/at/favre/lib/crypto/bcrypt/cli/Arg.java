package at.favre.lib.crypto.bcrypt.cli;

import java.util.Arrays;
import java.util.Objects;

/**
 * The model for the passed arguments
 */
public class Arg {
    //CHECKSTYLE:OFF -- I do want a concise class with only public access
    public char[] password;
    public String checkBcryptHash;
    public byte[] salt;
    public int costFactor;
    public int version;

    Arg() {
    }

    public Arg(char[] password, String checkBcryptHash, byte[] salt, int costFactor, int version) {
        this.password = password;
        this.checkBcryptHash = checkBcryptHash;
        this.salt = salt;
        this.costFactor = costFactor;
        this.version = version;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Arg arg = (Arg) o;
        return costFactor == arg.costFactor &&
                version == arg.version &&
                Arrays.equals(password, arg.password) &&
                Objects.equals(checkBcryptHash, arg.checkBcryptHash) &&
                Arrays.equals(salt, arg.salt);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(checkBcryptHash, costFactor, version);
        result = 31 * result + Arrays.hashCode(password);
        result = 31 * result + Arrays.hashCode(salt);
        return result;
    }

    @Override
    public String toString() {
        return "Arg{" +
                "password=" + Arrays.toString(password) +
                ", checkBcryptHash='" + checkBcryptHash + '\'' +
                ", salt=" + Arrays.toString(salt) +
                ", costFactor=" + costFactor +
                ", version=" + version +
                '}';
    }


    //CHECKSTYLE:ON
}