package at.favre.lib.crypto.bcrypt;

public class IllegalBCryptFormatException extends Exception {

    public IllegalBCryptFormatException(String s) {
        super(s);
    }

    public IllegalBCryptFormatException(String message, Throwable cause) {
        super(message, cause);
    }

    public IllegalBCryptFormatException(Throwable cause) {
        super(cause);
    }

    @Override
    public String getMessage() {
        return super.getMessage() + " - example of expected hash format: '$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i'" +
                " which includes 16 bytes salt and 23 bytes hash value encoded in a base64 flavor";
    }
}
