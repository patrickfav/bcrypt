package at.favre.lib.crypto.bcrypt;

/**
 * Exception thrown on parsing if an illegal format has been detected.
 * <p>
 * Heavily used in {@link BCryptParser}
 */
public class IllegalBCryptFormatException extends Exception {

    public IllegalBCryptFormatException(String s) {
        super(s);
    }

    @Override
    public String getMessage() {
        return super.getMessage() + " - example of expected hash format: '$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i'" +
                " which includes 16 bytes salt and 23 bytes hash value encoded in a base64 flavor";
    }
}
