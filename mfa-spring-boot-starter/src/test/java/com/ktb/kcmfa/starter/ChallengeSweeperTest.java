package com.ktb.kcmfa.starter;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ChallengeSweeperTest {

    @Test
    void sweepRevokesExpiredChallengesOnly() {
        KeycloakClient kc = mock(KeycloakClient.class);
        InMemoryChallengeStore store = new InMemoryChallengeStore();
        Challenge expired = store.create(Challenge.Type.VERIFY, "u1", "john",
                Map.of("refresh_token", "r1"), Duration.ofMillis(-1), false);
        Challenge live = store.create(Challenge.Type.VERIFY, "u2", "jane",
                Map.of("refresh_token", "r2"), Duration.ofMinutes(5), false);

        new ChallengeSweeper(store, kc, Duration.ofSeconds(30)).sweepOnce();

        verify(kc).logout("r1");
        verify(kc, never()).logout("r2");
        assertFalse(store.find(expired.id).isPresent());
        assertTrue(store.find(live.id).isPresent());
    }
}
