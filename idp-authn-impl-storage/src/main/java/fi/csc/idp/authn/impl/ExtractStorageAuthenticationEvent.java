/*
 * The MIT License
 * Copyright (c) 2018 CSC - IT Center for Science, http://www.csc.fi
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
import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.session.context.navigate.CanonicalUsernameLookupStrategy;

import org.opensaml.profile.action.ActionSupport;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import fi.csc.idp.authn.context.StorageAuthenticationContext;
import fi.csc.idp.authn.storage.AuthenticationEvent;
import fi.csc.idp.authn.storage.AuthenticationEventCache;

/**
 * Class locating existing storage authentication event on the basis of user authenticated by prior authentication flow
 * in mfa authentication sequence.
 */
@SuppressWarnings({"rawtypes"})
public class ExtractStorageAuthenticationEvent extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ExtractStorageAuthenticationEvent.class);

    /** Authentication event cache instance to use. */
    @NonnullAfterInit
    private AuthenticationEventCache authenticationEventCache;

    /** Lookup strategy for username to search authentication event for. */
    @Nonnull
    private Function<ProfileRequestContext, String> usernameLookupStrategy;

    /** User name of the user identified by previous MFA authentication. */
    @Nonnull
    private String username;

    /** Constructor. */
    ExtractStorageAuthenticationEvent() {
        usernameLookupStrategy = new CanonicalUsernameLookupStrategy();
    }

    /**
     * Set the lookup strategy to use for the username to search authentication event for.
     * 
     * @param strategy lookup strategy
     */
    public void setUsernameLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        usernameLookupStrategy = Constraint.isNotNull(strategy, "Username lookup strategy cannot be null");
    }

    /**
     * Get the authentication event cache instance to use.
     * 
     * @return Returns the authentication event cache.
     */
    @NonnullAfterInit
    public AuthenticationEventCache getAuthenticationEventCache() {
        return authenticationEventCache;
    }

    /**
     * Set the authentication event cache instance to use.
     * 
     * @param cache The authentication event cache to set.
     */
    public void setAuthenticationEventCache(@Nonnull final AuthenticationEventCache cache) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        authenticationEventCache = Constraint.isNotNull(cache, "authentication event cache cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        Constraint.isNotNull(getAuthenticationEventCache(), "authentication event cache cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        username = usernameLookupStrategy.apply(profileRequestContext);
        if (username == null) {
            log.warn("{} username is not available, nothing to do.", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        AuthenticationEvent event = authenticationEventCache.locate(username);
        StorageAuthenticationContext storageAuthenticationContext =
                authenticationContext.getSubcontext(StorageAuthenticationContext.class, true);
        storageAuthenticationContext.setUsername(username);
        storageAuthenticationContext.setAuthenticationEvent(event);
        if (event != null) {
            log.debug("{} Authentication event located {} for user {}, setting it to storage authentication context",
                    getLogPrefix(), event.serialize(), username);
            return;
        }
        log.debug("{} no user credentials, authentication event not available", getLogPrefix());
        ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
        return;
    }

}
