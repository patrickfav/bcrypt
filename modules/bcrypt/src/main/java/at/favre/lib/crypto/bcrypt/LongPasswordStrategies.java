package at.favre.lib.crypto.bcrypt;

/**
 * Factory for default {@link LongPasswordStrategy} implementatins
 */
@SuppressWarnings("WeakerAccess")
public final class LongPasswordStrategies {
    private LongPasswordStrategies() {
    }

    /**
     * See {@link at.favre.lib.crypto.bcrypt.LongPasswordStrategy.TruncateStrategy}
     *
     * @return new instance
     */
    public static LongPasswordStrategy truncate() {
        return new LongPasswordStrategy.TruncateStrategy(BCrypt.MAX_PW_LENGTH_BYTE);
    }

    /**
     * See {@link at.favre.lib.crypto.bcrypt.LongPasswordStrategy.Sha512DerivationStrategy}
     *
     * @return new instance
     */
    public static LongPasswordStrategy hashSha512() {
        return new LongPasswordStrategy.Sha512DerivationStrategy(BCrypt.MAX_PW_LENGTH_BYTE);
    }

    /**
     * See {@link at.favre.lib.crypto.bcrypt.LongPasswordStrategy.StrictMaxPasswordLengthStrategy}
     *
     * @return new instance
     */
    public static LongPasswordStrategy strict() {
        return new LongPasswordStrategy.StrictMaxPasswordLengthStrategy(BCrypt.MAX_PW_LENGTH_BYTE);
    }

    /**
     * See {@link LongPasswordStrategy.PassThroughStrategy}
     *
     * @return new instance
     */
    public static LongPasswordStrategy none() {
        return new LongPasswordStrategy.PassThroughStrategy();
    }
}
