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

import static spark.Spark.get;

import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.manager.user.UserManager;

import com.suse.manager.webui.services.OidcAuthException;
import com.suse.manager.webui.services.OidcAuthHandler;
import com.suse.manager.webui.utils.LoginHelper;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.security.auth.login.LoginException;

import spark.Request;
import spark.Response;

/**
 * Handles browser-based OpenID Connect (OIDC) single sign-on callbacks.
 */
public final class OidcController {

    public static final String OIDC_STATE_SESSION_ATTR = "oidc_state";
    public static final String OIDC_NONCE_SESSION_ATTR = "oidc_nonce";
    public static final String OIDC_URL_BOUNCE_SESSION_ATTR = "oidc_url_bounce";

    private static final Logger LOG = LogManager.getLogger(OidcController.class);

    private final OidcAuthHandler oidcAuthHandler;

    /**
     * Default constructor.
     * @param oidcAuthHandlerIn the OIDC handler
     */
    public OidcController(OidcAuthHandler oidcAuthHandlerIn) {
        this.oidcAuthHandler = oidcAuthHandlerIn;
    }

    /**
     * Method used to init routes in Spark.
     */
    public void initRoutes() {
        get("/manager/oidc/callback", this::handleCallback);
    }

    /**
     * Handles the OIDC authorization code callback from the identity provider.
     * @param request the Spark Request instance used in the current request scope
     * @param response the Spark Response instance used in the current response scope
     * @return the response object
     */
    public Object handleCallback(Request request, Response response) {
        if (!oidcAuthHandler.isBrowserLoginEnabled()) {
            LOG.error("OIDC callback received while browser login is disabled.");
            response.redirect("/");
            return response;
        }

        String error = request.queryParams("error");
        if (StringUtils.isNotEmpty(error)) {
            LOG.error("OIDC AUTH FAILURE: Identity provider returned error '{}'.", error);
            response.redirect("/");
            return response;
        }

        String state = request.queryParams("state");
        String expectedState = (String) request.raw().getSession().getAttribute(OIDC_STATE_SESSION_ATTR);
        if (StringUtils.isEmpty(state) || !state.equals(expectedState)) {
            LOG.error("OIDC AUTH FAILURE: Invalid OAuth state parameter.");
            response.redirect("/");
            return response;
        }

        String code = request.queryParams("code");
        if (StringUtils.isEmpty(code)) {
            LOG.error("OIDC AUTH FAILURE: Missing authorization code.");
            response.redirect("/");
            return response;
        }

        String expectedNonce = (String) request.raw().getSession().getAttribute(OIDC_NONCE_SESSION_ATTR);
        String urlBounce = (String) request.raw().getSession().getAttribute(OIDC_URL_BOUNCE_SESSION_ATTR);
        if (StringUtils.isEmpty(urlBounce)) {
            urlBounce = LoginHelper.DEFAULT_URL_BOUNCE;
        }

        request.raw().getSession().removeAttribute(OIDC_STATE_SESSION_ATTR);
        request.raw().getSession().removeAttribute(OIDC_NONCE_SESSION_ATTR);
        request.raw().getSession().removeAttribute(OIDC_URL_BOUNCE_SESSION_ATTR);

        try {
            String idToken = oidcAuthHandler.exchangeAuthorizationCode(code);
            String username = oidcAuthHandler.handleOidcLogin(idToken, expectedNonce);
            User user = UserManager.loginUser(username);
            LoginHelper.successfulLogin(request.raw(), response.raw(), user);
            LOG.info("OIDC AUTH SUCCESS: [{}]", user.getLogin());

            if (urlBounce.startsWith("/rhn/")) {
                response.redirect(urlBounce);
            }
            else {
                response.redirect(LoginHelper.DEFAULT_URL_BOUNCE);
            }
        }
        catch (OidcAuthException e) {
            LOG.error("OIDC AUTH FAILURE: Error during OIDC callback handling.", e);
            response.redirect("/");
        }
        catch (LoginException e) {
            LOG.error("OIDC AUTH FAILURE: User login failed during OIDC callback.", e);
            response.redirect("/");
        }

        return response;
    }
}
