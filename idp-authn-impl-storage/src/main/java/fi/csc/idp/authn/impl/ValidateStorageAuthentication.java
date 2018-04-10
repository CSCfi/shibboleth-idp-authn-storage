/*
 * The MIT License
 * Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package fi.csc.idp.authn.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;
import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.csc.idp.authn.context.StorageAuthenticationContext;

@SuppressWarnings("rawtypes")
public class ValidateStorageAuthentication extends AbstractValidationAction {

    /** Default prefix for metrics. */
    @Nonnull
    @NotEmpty
    private static final String DEFAULT_METRIC_NAME = "fi.csc.idp.authn.impl.storage";

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ValidateStorageAuthentication.class);

    /** Storage Authentication Event to evaluate. */
    @Nullable
    private StorageAuthenticationContext storageAuthenticationCtx;

    /** The principal name established by the action, if any. */
    @Nullable
    private String principalName;

    /** Constructor. */
    public ValidateStorageAuthentication() {
        /** todo: what? */
        setMetricName(DEFAULT_METRIC_NAME);
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }
        if (authenticationContext.getAttemptedFlow() == null) {
            log.debug("{} No attempted flow within authentication context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            recordFailure();
            return false;
        }
        storageAuthenticationCtx = authenticationContext.getSubcontext(StorageAuthenticationContext.class, false);
        if (storageAuthenticationCtx == null) {
            log.debug("{} No StorageAuthenticationContext available within authentication context", getLogPrefix());
            handleError(profileRequestContext, authenticationContext, "NoCredentials", AuthnEventIds.NO_CREDENTIALS);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        if (storageAuthenticationCtx.getAuthenticationEvent() != null) {
            principalName = storageAuthenticationCtx.getAuthenticationEvent().getSubject();
            log.info("{} Authenticated user as {}", getLogPrefix(), principalName);
            recordSuccess();
            buildAuthenticationResult(profileRequestContext, authenticationContext);
            return;
        }
        log.debug("{} User agent was not authenticated", getLogPrefix(), principalName);
        ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
        /*
         * handleError(profileRequestContext, authenticationContext, String.format("%s:%s", response.getResultCode(),
         * response.getMessage()), AuthnEventIds.INVALID_CREDENTIALS);
         */
        recordFailure();
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    protected Subject populateSubject(@Nonnull final Subject subject) {
        subject.getPrincipals().add(new UsernamePrincipal(principalName));
        return subject;
    }

}