package at.favre.lib.crypto.bcrypt;

final class BcryptTestEntry {
    public final String plainPw;
    public final int cost;
    public final String radix64Salt;
    public final String hash;

    public BcryptTestEntry(String plainPw, int cost, String radix64Salt, String hash) {
        this.plainPw = plainPw;
        this.cost = cost;
        this.radix64Salt = radix64Salt;
        this.hash = hash;
    }
}
