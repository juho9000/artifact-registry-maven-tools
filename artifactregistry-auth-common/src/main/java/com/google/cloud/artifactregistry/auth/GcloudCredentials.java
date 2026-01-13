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

import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.GenericData;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GcloudCredentials extends GoogleCredentials {
  private static final Logger LOGGER = LoggerFactory.getLogger(GcloudCredentials.class.getName());

  private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
  private static final String KEY_ACCESS_TOKEN = "access_token";
  private static final String KEY_TOKEN_EXPIRY = "token_expiry";

  // Rate limiting for refresh calls to avoid excessive gcloud invocations.
  // This is necessary because HttpCredentialsAdapter calls refreshIfExpired() on every
  // HTTP request, bypassing the rate limiting in DefaultCredentialProvider.
  // With per-lookup wagon instantiation, builds with many artifacts could trigger
  // a ton of gcloud CLI calls without this protection.
  static final long MIN_REFRESH_INTERVAL_MS = Duration.ofSeconds(15).toMillis();
  static final long MIN_TOKEN_LIFETIME_MS = Duration.ofSeconds(60).toMillis();
  private static final Object refreshLock = new Object();
  private static long lastRefreshTimeMs = 0;

  // Visible for testing
  static void resetRateLimitingState() {
    synchronized (refreshLock) {
      lastRefreshTimeMs = 0;
    }
  }

  private final CommandExecutor commandExecutor;


  public GcloudCredentials(
          AccessToken initialToken,
          CommandExecutor commandExecutor
  ) {
    super(initialToken);
    this.commandExecutor = commandExecutor;
  }

  /**
   * Tries to get credentials from gcloud. Returns null if credentials are not available.
   * @return The Credentials from gcloud
   * @throws IOException if there was an error retrieving credentials from gcloud
   */
  public static GcloudCredentials tryCreateGcloudCredentials(CommandExecutor commandExecutor) throws IOException {
    return new GcloudCredentials(validateAccessToken(getGcloudAccessToken(commandExecutor)), commandExecutor);
  }

  private static String gCloudCommand() {
    boolean isWindows = System.getProperty("os.name").startsWith("Windows");
    return isWindows ? "gcloud.cmd" : "gcloud";
  }

  // This is called if the token expires, from the calls to refreshIfExpired()
  // Rate limited to avoid excessive gcloud invocations during builds with many artifacts.
  @Override
  public AccessToken refreshAccessToken() throws IOException {
    synchronized (refreshLock) {
      long now = Instant.now().toEpochMilli();

      // Check if we refreshed recently
      if ((now - lastRefreshTimeMs) < MIN_REFRESH_INTERVAL_MS) {
        AccessToken currentToken = getAccessToken();
        if (currentToken != null) {
          // Only return cached token if it has enough lifetime remaining
          Date expiry = currentToken.getExpirationTime();
          if (expiry != null) {
            long timeUntilExpiry = expiry.getTime() - now;
            if (timeUntilExpiry > MIN_TOKEN_LIFETIME_MS) {
              LOGGER.debug("Skipping refresh, token still valid for {}ms", timeUntilExpiry);
              return currentToken;
            }
          }
          // Token has no expiry or is expiring very soon, allow refresh even within rate limit
        }
      }

      LOGGER.info("Refreshing gcloud credentials...");
      AccessToken newToken = validateAccessToken(getGcloudAccessToken(this.commandExecutor));
      lastRefreshTimeMs = now;
      return newToken;
    }
  }

  // Checks that the token is valid, throws IOException if it is expired.
  // If this plugin is run when gcloud has expired auth, then it gcloud doesn't
  // throw any errors, it simply returns an expired token. We check the token
  // that is returned and throw an error if it's expired to prompt the user to
  // login.
  private static AccessToken validateAccessToken(AccessToken token) throws IOException {
      Date expiry = token.getExpirationTime();
      if (expiry != null && expiry.before(new Date())) {
        throw new IOException("AccessToken is expired - maybe run `gcloud auth login`");
      }
      return token;
  }

  private static AccessToken getGcloudAccessToken(CommandExecutor commandExecutor) throws IOException {
    try {
      String gcloud = gCloudCommand();
      CommandExecutorResult commandExecutorResult = commandExecutor.executeCommand(gcloud, "config", "config-helper", "--format=json(credential)");
      int exitCode = commandExecutorResult.exitCode;
      String stdOut = commandExecutorResult.stdOut;

      if (exitCode != 0) {
        String stdErr = commandExecutorResult.stdErr;
        throw new IOException(String.format("gcloud exited with status: %d\nOutput:\n%s\nError Output:\n%s\n",
            exitCode, stdOut, stdErr));
      }

      GenericData result = JSON_FACTORY.fromString(stdOut, GenericData.class);
      Map credential = (Map) result.get("credential");
      if (credential == null) {
        throw new IOException("No credential returned from gcloud");
      }
      if (!credential.containsKey(KEY_ACCESS_TOKEN) || !credential.containsKey(KEY_TOKEN_EXPIRY)) {
        throw new IOException("Malformed response from gcloud");
      }
      DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
      df.setTimeZone(TimeZone.getTimeZone("UTC"));
      Date expiry = df.parse((String) credential.get(KEY_TOKEN_EXPIRY));
      return new AccessToken((String) credential.get(KEY_ACCESS_TOKEN), expiry);
    } catch (ParseException e) {
      throw new IOException("Failed to parse timestamp from gcloud output", e);
    }
  }
}
