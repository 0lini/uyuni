/*
 * Copyright (c) 2026 SUSE LLC
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 */
package com.suse.manager.webui.controllers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.redhat.rhn.common.conf.Config;
import com.redhat.rhn.common.conf.ConfigDefaults;
import com.redhat.rhn.common.util.http.HttpClientAdapter;
import com.redhat.rhn.testing.RhnMockHttpServletResponse;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.suse.manager.webui.services.OidcAuthHandler;
import com.suse.manager.webui.utils.LoginHelper;

import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import spark.Request;
import spark.Response;

public class OidcControllerTest extends BaseControllerTestCase {

    private static final String ISSUER = "https://auth.localhost";
    private static final String TEST_KID = "test-key-id";
    private static final String JWKS_URI = "/.well-known/jwks.json";
    private static final String USERNAME_CLAIM = ConfigDefaults.get().getOidcUsernameClaim();
    private static final String MLM_AUDIENCE = ConfigDefaults.get().getOidcAudience();
    private static final String MCP_AUDIENCE = "mcp-server-uyuni";

    private OidcController oidcController;
    private KeyPair rsaKeyPair;

    @BeforeEach
    public void setUpOidcControllerTest() throws Exception {
        rsaKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        enableOidcBrowserLogin();
        oidcController = new OidcController(getHandler());
    }

    @Test
    public void testCallbackWithoutBrowserLogin() {
        Config.get().setString(ConfigDefaults.OIDC_CLIENT_ID, "");
        oidcController = new OidcController(new OidcAuthHandler());

        Request request = getRequestWithCsrfAndParams("/manager/oidc/callback",
                Map.of("code", "abc", "state", "state"));
        oidcController.handleCallback(request, response);

        RhnMockHttpServletResponse mockResponse = (RhnMockHttpServletResponse) response.raw();
        assertEquals("/", mockResponse.getRedirect());
    }

    @Test
    public void testCallbackWithInvalidStateRedirectsToRoot() {
        Request request = getRequestWithCsrfAndParams("/manager/oidc/callback",
                Map.of("code", "abc", "state", "wrong-state"));
        request.raw().getSession().setAttribute(OidcController.OIDC_STATE_SESSION_ATTR, "expected-state");

        oidcController.handleCallback(request, response);

        RhnMockHttpServletResponse mockResponse = (RhnMockHttpServletResponse) response.raw();
        assertEquals("/", mockResponse.getRedirect());
    }

    @Test
    public void testSuccessfulCallback() throws JoseException {
        WireMockServer wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        wireMockServer.start();
        try {
            String issuer = "http://localhost:" + wireMockServer.port();
            String tokenEndpoint = issuer + "/token";
            String jwksUri = issuer + JWKS_URI;
            String nonce = "nonce-123";
            String oidcConfig = String.format(
                    "{\"authorization_endpoint\":\"%s/authorize\",\"token_endpoint\":\"%s\",\"jwks_uri\":\"%s\"}",
                    issuer, tokenEndpoint, jwksUri);

            wireMockServer.stubFor(WireMock.get(OidcAuthHandler.OIDC_DISCOVERY_PATH)
                    .willReturn(WireMock.aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody(oidcConfig)));

            Config.get().setString(ConfigDefaults.OIDC_IDP_ISSUER, issuer);
            Config.get().setString(ConfigDefaults.OIDC_IDP_JWKS_PATH, "");
            oidcController = new OidcController(getHandler(new HttpClientAdapter()));

            String idTokenForCallback = issueValidToken(issuer, nonce);
            wireMockServer.stubFor(WireMock.post("/token")
                    .willReturn(WireMock.aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody(String.format("{\"id_token\":\"%s\"}", idTokenForCallback))));

            Request request = getRequestWithCsrfAndParams("/manager/oidc/callback",
                    Map.of("code", "auth-code", "state", "state-123"));
            request.raw().getSession().setAttribute(OidcController.OIDC_STATE_SESSION_ATTR, "state-123");
            request.raw().getSession().setAttribute(OidcController.OIDC_NONCE_SESSION_ATTR, nonce);
            request.raw().getSession().setAttribute(OidcController.OIDC_URL_BOUNCE_SESSION_ATTR,
                    LoginHelper.DEFAULT_URL_BOUNCE);

            Response callbackResponse = response;
            oidcController.handleCallback(request, callbackResponse);

            RhnMockHttpServletResponse mockResponse = (RhnMockHttpServletResponse) callbackResponse.raw();
            assertNotNull(mockResponse.getRedirect());
            assertTrue(mockResponse.getRedirect().startsWith(LoginHelper.DEFAULT_URL_BOUNCE));
        }
        finally {
            wireMockServer.stop();
        }
    }

    private OidcAuthHandler getHandler() throws JoseException {
        return getHandler(new HttpClientAdapter());
    }

    private OidcAuthHandler getHandler(HttpClientAdapter httpClient) throws JoseException {
        PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(rsaKeyPair.getPublic());
        jwk.setKeyId(TEST_KID);
        VerificationKeyResolver keyResolver = new JwksVerificationKeyResolver(new JsonWebKeySet(jwk).getJsonWebKeys());
        return new OidcAuthHandler(keyResolver, httpClient);
    }

    private void enableOidcBrowserLogin() {
        Config.get().setBoolean(ConfigDefaults.OIDC_ENABLED, "true");
        Config.get().setString(ConfigDefaults.OIDC_IDP_ISSUER, ISSUER);
        Config.get().setString(ConfigDefaults.OIDC_IDP_JWKS_PATH, JWKS_URI);
        Config.get().setString(ConfigDefaults.OIDC_CLIENT_ID, "uyuni-client");
        Config.get().setString(ConfigDefaults.OIDC_CLIENT_SECRET, "client-secret");
        Config.get().setString(ConfigDefaults.OIDC_REDIRECT_URI, "https://uyuni.example/rhn/manager/oidc/callback");
        Config.get().setString(ConfigDefaults.OIDC_SCOPES, "openid profile");
    }

    private String issueValidToken(String issuer, String nonce) throws JoseException {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(issuer);
        claims.setSubject(UUID.randomUUID().toString());
        claims.setExpirationTimeMinutesInTheFuture(10);
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        claims.setAudience(List.of(MCP_AUDIENCE, MLM_AUDIENCE));
        claims.setClaim(USERNAME_CLAIM, user.getLogin());
        claims.setClaim("nonce", nonce);

        org.jose4j.jws.JsonWebSignature jws = new org.jose4j.jws.JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(rsaKeyPair.getPrivate());
        jws.setKeyIdHeaderValue(TEST_KID);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        return jws.getCompactSerialization();
    }
}
