package at.favre.lib.crypto.bcrypt;

public final class LongPasswordStrategies {
    private LongPasswordStrategies() {
    }

    static LongPasswordStrategy truncate() {
        return new LongPasswordStrategy.TruncateStrategy(BCrypt.MAX_PW_LENGTH_BYTE);
    }

    static LongPasswordStrategy hashSha512() {
        return new LongPasswordStrategy.Sha512DerivationStrategy(BCrypt.MAX_PW_LENGTH_BYTE);
    }

    static LongPasswordStrategy strict() {
        return new LongPasswordStrategy.StrictMaxPasswordLengthStrategy(BCrypt.MAX_PW_LENGTH_BYTE);
    }
}
