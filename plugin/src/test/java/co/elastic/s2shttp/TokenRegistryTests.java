package co.elastic.s2shttp;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TokenRegistryTests {

    static final String A = "a3f5c2e1-7b4d-4e8f-9c6a-1d2e3f4a5b6c";
    static final String B = "8c1d9b2e-4a7f-4e0b-9d3c-2f6a1b5e7c90";

    @Test
    void namedAndUnnamedFingerprints() {
        TokenRegistry r = new TokenRegistry();
        assertNull(r.match(A), "empty list allows nothing");
        r.set(List.of("dc1-linux=" + RequestInfo.sha256(A).toUpperCase(Locale.ROOT), RequestInfo.sha256(B)));
        assertEquals("dc1-linux", r.match(A));
        assertEquals("", r.match(B));
        assertEquals("dc1-linux", r.nameForHash(RequestInfo.sha256(A)));
        assertNull(r.nameForHash(RequestInfo.sha256(B)));
        assertNull(r.match("11111111-2222-3333-4444-555555555555"));
        assertNull(r.match(RequestInfo.sha256(A)), "presenting the fingerprint itself must not authenticate");
        r.set(List.of(RequestInfo.sha256(B)));
        assertNull(r.match(A), "each update replaces the list");
    }

    @Test
    void rejectsBadEntries() {
        assertThrows(IllegalArgumentException.class, () -> TokenRegistry.validate(List.of("not-a-hash")));
        assertThrows(IllegalArgumentException.class, () -> TokenRegistry.validate(List.of("bad name!=" + RequestInfo.sha256(A))));
    }
}
