package at.favre.lib.crypto.bcrypt.misc;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bcrypt.Radix64Encoder;

@SuppressWarnings("unused")
public class Radix64RefDataCreator {
    private final Radix64Encoder encoder;
    private final int byteLength;

    public Radix64RefDataCreator(Radix64Encoder encoder, int byteLength) {
        this.encoder = encoder;
        this.byteLength = byteLength;
    }

    public void printRefData() {
        for (int i = 0; i < 256; i++) {
            testSingleEncode(byteLength);
        }
    }

    private void testSingleEncode(int length) {
        byte[] rnd = Bytes.random(length).array();
        byte[] encoded = encoder.encode(rnd);
        byte[] decoded = encoder.decode(encoded);

        if (!Bytes.wrap(rnd).equals(decoded)) throw new IllegalStateException("encoded/decoded does not match");

        System.out.println("new EncodeTestCase(\"" + Bytes.wrap(encoded).encodeUtf8() + "\"," + new JavaByteArrayEncoder().encode(rnd) + "),");
    }

    public static final class JavaByteArrayEncoder {
        interface ByteEncoder {
            String encodeByte(byte b);
        }

        String encodeInternal(byte[] array, String prefix, String postfix, String sep, ByteEncoder byteEncoder) {
            StringBuilder sb = new StringBuilder(prefix);
            for (byte anArray : array) {
                sb.append(byteEncoder.encodeByte(anArray)).append(sep).append(" ");
            }

            sb.replace(sb.length() - 2, sb.length(), postfix);
            return sb.toString();
        }

        public String encode(byte[] array) {
            return encodeInternal(array, "new byte[]{", "}", ",", new ByteEncoder() {
                @Override
                public String encodeByte(byte b) {
                    StringBuilder sb = new StringBuilder();
                    if ((b & 0xFF) >= 127) {
                        sb.append("(byte) ");
                    }
                    sb.append("0x").append(Bytes.from(b).encodeHex(true));
                    return sb.toString();
                }
            });
        }
    }
}
