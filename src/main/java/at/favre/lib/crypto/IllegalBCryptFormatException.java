package at.favre.lib.crypto;

public class IllegalBCryptFormatException extends IllegalArgumentException {

    public IllegalBCryptFormatException(String s) {
        super(s);
    }

    public IllegalBCryptFormatException(String message, Throwable cause) {
        super(message, cause);
    }

    public IllegalBCryptFormatException(Throwable cause) {
        super(cause);
    }
}
