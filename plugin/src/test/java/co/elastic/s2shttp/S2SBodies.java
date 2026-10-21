package co.elastic.s2shttp;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.DeflaterOutputStream;

/** Builds S2S request bodies for tests: one meta record, then event records. */
final class S2SBodies {
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    S2SBodies meta(long headerCount) {
        out.write(0xfe);
        varint(1);
        nstr("source::/var/log/x.log");
        nstr("host::h1");
        nstr("sourcetype::st");
        nstr("ch");
        varint(headerCount);
        return this;
    }

    /** {@code n} event records with this text, each at its own file offset. */
    S2SBodies events(int n, String raw) {
        for (int i = 0; i < n; i++) {
            out.write(0xfc);
            varint(1);
            varint(0x23b);
            varint(7);
            varint(i * 100L);
            varint(i);
            varint(1_790_000_000L);
            varint(0);
            str(raw);
        }
        return this;
    }

    byte[] inflated() {
        return out.toByteArray();
    }

    /** As the forwarder sends it: 0xf9 and zlib. */
    byte[] body() {
        ByteArrayOutputStream z = new ByteArrayOutputStream();
        z.write(0xf9);
        try (DeflaterOutputStream d = new DeflaterOutputStream(z)) {
            d.write(out.toByteArray());
        } catch (java.io.IOException e) {
            throw new AssertionError(e);
        }
        return z.toByteArray();
    }

    private void varint(long v) {
        while ((v & ~0x7fL) != 0) {
            out.write((int) ((v & 0x7f) | 0x80));
            v >>>= 7;
        }
        out.write((int) v);
    }

    private void str(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        varint(b.length);
        out.writeBytes(b);
    }

    private void nstr(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        varint(b.length + 1);
        out.writeBytes(b);
    }
}
