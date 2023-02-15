package at.favre.lib.crypto.bcrypt;

import java.util.Objects;

/**
 * Factory for default {@link LongPasswordStrategy} implementations
 */
@SuppressWarnings("WeakerAccess")
public final class LongPasswordStrategies {
    private LongPasswordStrategies() {
    }

    /**
     * See {@link at.favre.lib.crypto.bcrypt.LongPasswordStrategy.TruncateStrategy}
     *
     * @param version required to get the max allowed pw length
     * @return new instance
     */
    public static LongPasswordStrategy truncate(BCrypt.Version version) {
        return new LongPasswordStrategy.TruncateStrategy(Objects.requireNonNull(version).allowedMaxPwLength);
    }

    /**
     * See {@link at.favre.lib.crypto.bcrypt.LongPasswordStrategy.Sha512DerivationStrategy}
     *
     * @param version required to get the max allowed pw length
     * @return new instance
     */
    public static LongPasswordStrategy hashSha512(BCrypt.Version version) {
        return new LongPasswordStrategy.Sha512DerivationStrategy(Objects.requireNonNull(version).allowedMaxPwLength);
    }

    /**
     * See {@link at.favre.lib.crypto.bcrypt.LongPasswordStrategy.StrictMaxPasswordLengthStrategy}
     *
     * @param version required to get the max allowed pw length
     * @return new instance
     */
    public static LongPasswordStrategy strict(BCrypt.Version version) {
        return new LongPasswordStrategy.StrictMaxPasswordLengthStrategy(Objects.requireNonNull(version).allowedMaxPwLength);
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
