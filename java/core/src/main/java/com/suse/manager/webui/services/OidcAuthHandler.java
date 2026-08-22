/*
 * Copyright (c) 2025 SUSE LLC
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * Red Hat trademarks are not licensed under GPLv2. No permission is
 * granted to use or replicate Red Hat trademarks that are incorporated
 * in this software or its documentation.
 */
package com.suse.manager.webui.services;

import com.redhat.rhn.common.conf.ConfigDefaults;
import com.redhat.rhn.common.conf.ConfigException;
import com.redhat.rhn.common.util.http.HttpClientAdapter;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Handles OpenID Connect (OIDC) authorization.
 */
public class OidcAuthHandler {

    public static final String OIDC_DISCOVERY_PATH = "/.well-known/openid-configuration";

    private static final Logger LOG = LogManager.getLogger(OidcAuthHandler.class);

    private boolean oidcEnabled;
    private String issuer;
    private volatile String jwksUri;
    private volatile String authorizationEndpoint;
    private volatile String tokenEndpoint;
    private String audience;
    private String usernameClaim;
    private String clientId;
    private String clientSecret;
    private String redirectUri;
    private String scopes;

    private final AtomicReference<JwtConsumer> jwtConsumer = new AtomicReference<>();
    private final VerificationKeyResolver keyResolver;
    private final HttpClientAdapter httpClient;

    /**
     * Constructs an OidcAuthHandler and loads configuration.
     */
    public OidcAuthHandler() {
        this(null, new HttpClientAdapter());
    }

    /**
     * Constructs an OidcAuthHandler with a custom {@link VerificationKeyResolver}.
     *
     * @param keyResolverIn the verification key resolver, if {@code null} a default one is created
     * @param httpClientIn the HTTP client to use when fetching from the discovery endpoint
     */
    public OidcAuthHandler(VerificationKeyResolver keyResolverIn, HttpClientAdapter httpClientIn) {
        this.httpClient = httpClientIn;
        this.keyResolver = keyResolverIn;

        try {
            loadConfiguration();
            if (!isOidcEnabled()) {
                return;
            }
        }
        catch (URISyntaxException eIn) {
            throw new ConfigException("Malformed URI in the OIDC configuration.");
        }

        try {
            initJwtConsumer();
        }
        catch (OidcAuthException e) {
            LOG.warn("OIDC JWT consumer initialization failed during startup. " +
                    "Will retry on subsequent login attempts.", e);
        }
    }

    private JwtConsumer buildJwtConsumer(VerificationKeyResolver resolver) {

        AlgorithmConstraints jwsAlgConstraints = new AlgorithmConstraints(
                AlgorithmConstraints.ConstraintType.PERMIT,
                AlgorithmIdentifiers.RSA_USING_SHA256,
                AlgorithmIdentifiers.RSA_USING_SHA384,
                AlgorithmIdentifiers.RSA_USING_SHA512,
                AlgorithmIdentifiers.RSA_PSS_USING_SHA256,
                AlgorithmIdentifiers.RSA_PSS_USING_SHA384,
                AlgorithmIdentifiers.RSA_PSS_USING_SHA512,
                AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256,
                AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384
        );

        return new JwtConsumerBuilder()
                .setVerificationKeyResolver(resolver)
                .setJweAlgorithmConstraints(jwsAlgConstraints)
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(5)
                .setRequireSubject()
                .setExpectedIssuer(true, issuer)
                .setSkipDefaultAudienceValidation()
                .build();
    }

    private synchronized void initJwtConsumer() throws OidcAuthException {
        if (!isOidcEnabled() || this.jwtConsumer.get() != null) {
            return;
        }

        VerificationKeyResolver resolver = keyResolver;
        if (resolver == null) {
            if (StringUtils.isEmpty(jwksUri)) {
                try {
                    this.jwksUri = fetchJwksUri(new URI(issuer));
                }
                catch (URISyntaxException | ConfigException e) {
                    throw new OidcAuthException("JWKS URI is not available from the OIDC discovery endpoint.", e);
                }
            }

            HttpsJwks httpsJwks = new HttpsJwks(jwksUri);

            // No proxy support in jose4j
            // HttpsJwks can be subclassed for proxy support
            resolver = new HttpsJwksVerificationKeyResolver(httpsJwks);
        }

        this.jwtConsumer.set(buildJwtConsumer(resolver));
        LOG.info("OIDC authorization is enabled. Issuer: {}, Audience: {}, Username attribute: {}",
                issuer, audience, usernameClaim);
    }

    /**
     * Loads OIDC configuration from {@link ConfigDefaults}.
     * @throws URISyntaxException if a malformed URI is encountered.
     */
    private void loadConfiguration() throws URISyntaxException {
        LOG.debug("Loading OIDC configuration.");
        oidcEnabled = ConfigDefaults.get().isOidcEnabled();

        if (!oidcEnabled) {
            LOG.debug("OIDC authorization is disabled.");
            return;
        }

        issuer = ConfigDefaults.get().getOidcIssuer();
        if (StringUtils.isEmpty(issuer)) {
            throw new ConfigException("OIDC issuer URI cannot be empty.");
        }
        URI issuerUri = new URI(issuer);

        audience = ConfigDefaults.get().getOidcAudience();
        if (StringUtils.isEmpty(audience)) {
            throw new ConfigException("OIDC audience cannot be empty.");
        }

        usernameClaim = ConfigDefaults.get().getOidcUsernameClaim();
        if (StringUtils.isEmpty(usernameClaim)) {
            throw new ConfigException("OIDC username claim name cannot be empty.");
        }

        clientId = ConfigDefaults.get().getOidcClientId();
        clientSecret = ConfigDefaults.get().getOidcClientSecret();
        redirectUri = ConfigDefaults.get().getOidcRedirectUri();
        scopes = ConfigDefaults.get().getOidcScopes();
        if (StringUtils.isEmpty(scopes)) {
            throw new ConfigException("OIDC scopes cannot be empty.");
        }

        String jwksPath = ConfigDefaults.get().getOidcJwksPath();
        if (StringUtils.isEmpty(jwksPath)) {
            LOG.info("JWKS path not provided. Will fetch from the OIDC discovery endpoint.");
        }
        else {
            this.jwksUri = appendUriPath(issuerUri, jwksPath).toString();
        }
    }

    /**
     * Fetches the OIDC discovery document from the issuing identity provider.
     * @param issuerIn The OIDC issuer URI.
     * @return The discovery document.
     * @throws URISyntaxException if a malformed URI is encountered.
     */
    private JsonObject fetchDiscoveryDocument(URI issuerIn) throws URISyntaxException {
        URI discoveryEndpoint = appendUriPath(issuerIn, OIDC_DISCOVERY_PATH);
        LOG.info("Fetching OIDC discovery document from: {}", discoveryEndpoint);

        HttpGet request = new HttpGet(discoveryEndpoint);
        HttpResponse response;

        try {
            response = httpClient.executeRequest(request);
            int statusCode = response.getStatusLine().getStatusCode();

            if (statusCode != 200) {
                throw new ConfigException("Failed to fetch OIDC discovery document from " + discoveryEndpoint +
                        ". HTTP status code: " + statusCode);
            }

            String jsonResponse = EntityUtils.toString(response.getEntity());
            JsonObject jsonObject = new Gson().fromJson(jsonResponse, JsonObject.class);

            if (jsonObject == null) {
                throw new ConfigException("OIDC discovery document from " + discoveryEndpoint + " is empty.");
            }

            return jsonObject;
        }
        catch (IOException e) {
            throw new ConfigException("Error while fetching OIDC discovery document from " + discoveryEndpoint, e);
        }
        finally {
            request.releaseConnection();
        }
    }

    private synchronized void ensureDiscoveryEndpoints() throws OidcAuthException {
        if (!isBrowserLoginEnabled() || StringUtils.isNotEmpty(authorizationEndpoint)) {
            return;
        }

        try {
            JsonObject discoveryDocument = fetchDiscoveryDocument(new URI(issuer));
            authorizationEndpoint = getRequiredDiscoveryValue(discoveryDocument, "authorization_endpoint");
            tokenEndpoint = getRequiredDiscoveryValue(discoveryDocument, "token_endpoint");

            if (StringUtils.isEmpty(jwksUri)) {
                jwksUri = getRequiredDiscoveryValue(discoveryDocument, "jwks_uri");
            }
        }
        catch (URISyntaxException | ConfigException e) {
            throw new OidcAuthException("OIDC discovery document is not available.", e);
        }
    }

    private static String getRequiredDiscoveryValue(JsonObject discoveryDocument, String key) {
        if (!discoveryDocument.has(key) || discoveryDocument.get(key).isJsonNull()) {
            throw new ConfigException("Required field '" + key + "' not found in the OIDC discovery document.");
        }

        String value = discoveryDocument.get(key).getAsString();
        if (StringUtils.isEmpty(value)) {
            throw new ConfigException("Required field '" + key + "' not found in the OIDC discovery document.");
        }

        return value;
    }

    /**
     * Fetches the JWKS URI from the OIDC discovery endpoint of the issuing identity provider.
     * @param issuerIn The OIDC issuer URI.
     * @return The JWKS URI.
     * @throws URISyntaxException if a malformed URI is encountered.
     */
    private String fetchJwksUri(URI issuerIn) throws URISyntaxException {
        JsonObject discoveryDocument = fetchDiscoveryDocument(issuerIn);
        String uri = getRequiredDiscoveryValue(discoveryDocument, "jwks_uri");
        LOG.debug("Successfully fetched JWKS URI: {}", uri);
        return uri;
    }

    /**
     * Appends a path to a base URI.
     * <p>
     * If the base URI includes a path itself, it is concatenated with the path to be appended.
     * @param base The base URI.
     * @param path The path to append.
     * @return The new URI with the appended path.
     * @throws URISyntaxException if a malformed URI is encountered.
     */
    private static URI appendUriPath(URI base, String path) throws URISyntaxException {
        if (StringUtils.isEmpty(path)) {
            return base;
        }

        String basePath = base.getPath();
        if (!basePath.endsWith("/")) {
            basePath += "/";
        }

        // Remove trailing slashes in path
        String normalizedPath = path.replaceAll("^/+", "");

        return new URIBuilder(base)
                .setPath(basePath + normalizedPath)
                .build();
    }

    /**
     * Handles OIDC login by verifying the provided token using a {@link JwtConsumer}.
     * <p>
     * Following validations are applied to the token:
     * <ul>
     *     <li>Signature verification using keys from the JWKS URI.</li>
     *     <li>Allowed JWS algorithms: RSA/PSS SHA-256, SHA-384, SHA-512 and ESDCA SHA-256, SHA-384.</li>
     *     <li>Requires an expiration time claim.</li>
     *     <li>Allows for a 5-second clock skew.</li>
     *     <li>Requires a subject claim.</li>
     *     <li>Validates the issuer claim against the configured OIDC issuer.</li>
     *     <li>Custom audience validation against the configured OIDC audience.</li>
     *     <li>Matches the configured Uyuni username claim to an existing user.</li>
     * </ul>
     * @param token The OIDC token.
     * @return The username claim.
     * @throws OidcAuthException if token verification fails or OIDC is not enabled.
     */
    public String handleOidcLogin(String token) throws OidcAuthException {
        return handleOidcLogin(token, null);
    }

    /**
     * Handles OIDC login by verifying the provided token using a {@link JwtConsumer}.
     * @param token The OIDC token.
     * @param expectedNonce Optional nonce claim value to validate for browser-based login.
     * @return The username claim.
     * @throws OidcAuthException if token verification fails or OIDC is not enabled.
     */
    public String handleOidcLogin(String token, String expectedNonce) throws OidcAuthException {
        if (!isOidcEnabled()) {
            throw new OidcAuthException("OIDC authorization is not enabled.");
        }

        initJwtConsumer();

        try {
            JwtClaims claims = jwtConsumer.get().processToClaims(token);
            if (!claims.getAudience().contains(audience)) {
                throw new OidcAuthException("Token verification failed. Missing '" + audience +
                        "' in the audience claim.");
            }
            if (!claims.hasClaim(usernameClaim)) {
                throw new OidcAuthException("Token verification failed. Missing '" + usernameClaim + "' claim.");
            }
            if (expectedNonce != null) {
                String nonce = claims.getClaimValueAsString("nonce");
                if (!expectedNonce.equals(nonce)) {
                    throw new OidcAuthException("Token verification failed. Nonce claim mismatch.");
                }
            }
            return claims.getClaimValueAsString(usernameClaim);
        }
        catch (InvalidJwtException | MalformedClaimException e) {
            throw new OidcAuthException("Token verification failed.", e);
        }
    }

    /**
     * Builds the authorization URL for browser-based OIDC SSO login.
     * @param state OAuth2 state parameter for CSRF protection
     * @param nonce OIDC nonce parameter for replay protection
     * @return the authorization URL
     * @throws OidcAuthException if browser login is not configured or discovery fails
     */
    public String buildAuthorizationUrl(String state, String nonce) throws OidcAuthException {
        if (!isBrowserLoginEnabled()) {
            throw new OidcAuthException("OIDC browser login is not configured.");
        }

        ensureDiscoveryEndpoints();

        try {
            return new URIBuilder(authorizationEndpoint)
                    .addParameter("response_type", "code")
                    .addParameter("client_id", clientId)
                    .addParameter("redirect_uri", getEffectiveRedirectUri())
                    .addParameter("scope", scopes)
                    .addParameter("state", state)
                    .addParameter("nonce", nonce)
                    .build()
                    .toString();
        }
        catch (URISyntaxException e) {
            throw new OidcAuthException("Unable to build OIDC authorization URL.", e);
        }
    }

    /**
     * Exchanges an authorization code for an ID token.
     * @param code The authorization code returned by the identity provider
     * @return The ID token
     * @throws OidcAuthException if the token exchange fails
     */
    public String exchangeAuthorizationCode(String code) throws OidcAuthException {
        if (!isBrowserLoginEnabled()) {
            throw new OidcAuthException("OIDC browser login is not configured.");
        }

        ensureDiscoveryEndpoints();

        HttpPost request = new HttpPost(tokenEndpoint);
        List<BasicNameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "authorization_code"));
        params.add(new BasicNameValuePair("code", code));
        params.add(new BasicNameValuePair("redirect_uri", getEffectiveRedirectUri()));
        params.add(new BasicNameValuePair("client_id", clientId));
        if (StringUtils.isNotEmpty(clientSecret)) {
            params.add(new BasicNameValuePair("client_secret", clientSecret));
        }

        try {
            request.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));
            request.setHeader("Accept", "application/json");
            HttpResponse response = httpClient.executeRequest(request);
            int statusCode = response.getStatusLine().getStatusCode();
            String jsonResponse = EntityUtils.toString(response.getEntity());

            if (statusCode != 200) {
                throw new OidcAuthException("OIDC token exchange failed with HTTP status code " + statusCode + ".");
            }

            JsonObject tokenResponse = new Gson().fromJson(jsonResponse, JsonObject.class);
            if (tokenResponse == null || !tokenResponse.has("id_token") || tokenResponse.get("id_token").isJsonNull()) {
                throw new OidcAuthException("OIDC token response does not contain an id_token.");
            }

            String idToken = tokenResponse.get("id_token").getAsString();
            if (StringUtils.isEmpty(idToken)) {
                throw new OidcAuthException("OIDC token response does not contain an id_token.");
            }

            return idToken;
        }
        catch (IOException e) {
            throw new OidcAuthException("OIDC token exchange failed.", e);
        }
        finally {
            request.releaseConnection();
        }
    }

    /**
     * Returns the redirect URI used for browser-based OIDC SSO login.
     * @return the redirect URI
     */
    public String getEffectiveRedirectUri() {
        if (StringUtils.isNotEmpty(redirectUri)) {
            return redirectUri;
        }

        String scheme = ConfigDefaults.get().isSsl() ? "https" : "http";
        return scheme + "://" + ConfigDefaults.get().getHostname() + "/rhn/manager/oidc/callback";
    }

    /**
     * Checks if OIDC authorization is enabled by configuration.
     * @return {@code true} if OIDC is enabled, {@code false} otherwise.
     */
    public boolean isOidcEnabled() {
        return oidcEnabled;
    }

    /**
     * Checks if browser-based OIDC SSO login is configured.
     * @return {@code true} if browser login is configured, {@code false} otherwise.
     */
    public boolean isBrowserLoginEnabled() {
        return ConfigDefaults.get().isOidcBrowserLoginEnabled();
    }

    /**
     * Gets the configured JWKS URI
     * @return the JWKS URI
     */
    public String getJwksUri() {
        return jwksUri;
    }
}
