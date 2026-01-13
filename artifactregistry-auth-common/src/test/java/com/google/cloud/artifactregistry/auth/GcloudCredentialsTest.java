/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.cloud.artifactregistry.auth;

import com.google.auth.oauth2.AccessToken;
import java.io.IOException;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class GcloudCredentialsTest {

  @Before
  public void setUp() {
    GcloudCredentials.resetRateLimitingState();
  }

  @After
  public void tearDown() {
    GcloudCredentials.resetRateLimitingState();
  }

  @Test
  public void testRefreshAccessTokenRateLimiting() throws Exception {
    AtomicInteger gcloudCallCount = new AtomicInteger(0);
    // Use a short expiry to trigger refresh, but not so short that MIN_TOKEN_LIFETIME_MS kicks in
    Date shortExpiry = Date.from(Instant.now().plusSeconds(30));
    Date longExpiry = Date.from(Instant.now().plusSeconds(600));

    GcloudCredentials credentials = new GcloudCredentials(
        new AccessToken("initial-token", shortExpiry),
        new CountingCommandExecutor(gcloudCallCount, longExpiry)
    );

    // First refresh should call gcloud
    credentials.refresh();
    Assert.assertEquals(1, gcloudCallCount.get());
    Assert.assertEquals("token-1", credentials.getAccessToken().getTokenValue());

    // Subsequent refreshes within the rate limit window should not call gcloud again
    // because the token now has longExpiry (> MIN_TOKEN_LIFETIME_MS)
    credentials.refresh();
    Assert.assertEquals(1, gcloudCallCount.get()); // Still 1, no new gcloud call

    credentials.refresh();
    Assert.assertEquals(1, gcloudCallCount.get()); // Still 1
  }

  @Test
  public void testRefreshAccessTokenAllowsRefreshWhenTokenExpiringSoon() throws Exception {
    AtomicInteger gcloudCallCount = new AtomicInteger(0);
    // Token expires in 30 seconds (less than MIN_TOKEN_LIFETIME_MS of 60 seconds)
    Date shortExpiry = Date.from(Instant.now().plusSeconds(30));

    // Create a command executor that always returns tokens with short expiry
    // This simulates the case where gcloud keeps returning near-expiry tokens
    GcloudCredentials credentials = new GcloudCredentials(
        new AccessToken("initial-token", shortExpiry),
        new CountingCommandExecutor(gcloudCallCount, shortExpiry)
    );

    // First refresh
    credentials.refresh();
    Assert.assertEquals(1, gcloudCallCount.get());

    // Even within rate limit window, should refresh because token is expiring soon
    // (less than MIN_TOKEN_LIFETIME_MS of 60 seconds)
    credentials.refresh();
    Assert.assertEquals(2, gcloudCallCount.get()); // Should have called gcloud again
  }

  @Test
  public void testRefreshAccessTokenValidatesToken() throws Exception {
    AtomicInteger gcloudCallCount = new AtomicInteger(0);
    // gcloud returns an expired token
    Date expiredDate = Date.from(Instant.now().minusSeconds(60));

    GcloudCredentials credentials = new GcloudCredentials(
        new AccessToken("initial-token", Date.from(Instant.now().plusSeconds(600))),
        new CountingCommandExecutor(gcloudCallCount, expiredDate)
    );

    try {
      credentials.refresh();
      Assert.fail("Expected IOException for expired token");
    } catch (IOException e) {
      Assert.assertTrue(e.getMessage().contains("expired"));
    }
  }

  private static class CountingCommandExecutor implements CommandExecutor {
    private final AtomicInteger callCount;
    private final Date tokenExpiry;

    CountingCommandExecutor(AtomicInteger callCount, Date tokenExpiry) {
      this.callCount = callCount;
      this.tokenExpiry = tokenExpiry;
    }

    @Override
    public CommandExecutorResult executeCommand(String command, String... args) throws IOException {
      int count = callCount.incrementAndGet();
      // Return a valid gcloud config-helper JSON response
      String jsonResponse = String.format(
          "{\"credential\":{\"access_token\":\"token-%d\",\"token_expiry\":\"%s\"}}",
          count,
          formatDate(tokenExpiry)
      );
      return new CommandExecutorResult(0, jsonResponse, "");
    }

    private String formatDate(Date date) {
      java.text.SimpleDateFormat df = new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
      df.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
      return df.format(date);
    }
  }
}
