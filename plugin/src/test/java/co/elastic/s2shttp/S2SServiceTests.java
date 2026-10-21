package co.elastic.s2shttp;

import org.elasticsearch.common.settings.Settings;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class S2SServiceTests {

    private static S2SService service(String... tokens) {
        List<String> fingerprints = java.util.Arrays.stream(tokens).map(RequestInfo::sha256).toList();
        return new S2SService(Settings.builder().putList("splunk_forwarders.token_sha256", fingerprints).build(), null, null);
    }

    @Test
    void tokenCheck() {
        S2SService svc = service("good");
        assertEquals(S2SService.NO_TOKEN, svc.checkToken(null));
        assertEquals(S2SService.NO_TOKEN, svc.checkToken(" "));
        assertNull(svc.checkToken("Splunk good"));
        assertNull(svc.checkToken("splunk good")); // the scheme is case-insensitive
        assertNull(svc.checkToken("Splunk good "));
        assertEquals(S2SService.BAD_TOKEN, svc.checkToken("Splunk "));
        assertEquals(S2SService.BAD_TOKEN, svc.checkToken("Splunk bad"));
        assertEquals(S2SService.BAD_TOKEN, service().checkToken("Splunk good")); // an empty list rejects everything
    }

    /** The fingerprint stored on documents is the one the token check matched. */
    @Test
    void storedFingerprintIsTheCheckedOne() {
        S2SDecoder.Batch none = new S2SDecoder.Batch(List.of(), 0);
        for (String header : List.of("Splunk good", "splunk good", "Splunk  good ", "good")) {
            RequestInfo r = RequestInfo.of("n", null, java.util.Map.of("Authorization", header), 0, none, 0, sha -> null);
            assertEquals(RequestInfo.sha256("good"), r.tokenSha256(), header);
        }
    }
}
