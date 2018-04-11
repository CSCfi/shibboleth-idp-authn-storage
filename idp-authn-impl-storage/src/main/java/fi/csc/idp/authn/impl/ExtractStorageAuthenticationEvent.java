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

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.MultiFactorAuthenticationContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import org.opensaml.profile.action.ActionSupport;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.google.common.base.Predicates;
import com.google.common.collect.Iterables;

import fi.csc.idp.authn.context.StorageAuthenticationContext;
import fi.csc.idp.authn.storage.AuthenticationEvent;
import fi.csc.idp.authn.storage.AuthenticationEventCache;

/**
 * Class locating existing storage authentication event on the basis of user authenticated by prior authentication flow
 * in mfa authentication sequence. The authentication flows providing user information are presented in order of
 * preference and set by setStorageUsernameAuthenticationFlowDescriptors. The first authentication event located is
 * stored to context for further evaluation.
 */
@SuppressWarnings({"rawtypes"})
public class ExtractStorageAuthenticationEvent extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ExtractStorageAuthenticationEvent.class);

    /** Authentication event cache instance to use. */
    @NonnullAfterInit
    private AuthenticationEventCache authenticationEventCache;

    /** Lookup function for the context to evaluate. */
    @Nonnull
    private Function<ProfileRequestContext, MultiFactorAuthenticationContext> multiFactorContextLookupStrategy;

    /** A subordinate {@link MultiFactorAuthenticationContext}, if any. */
    @Nullable
    private MultiFactorAuthenticationContext mfaContext;

    /** User name of the user identified by previous MFA authentication. */
    @Nonnull
    private List<String> usernames;

    /** Flows that provide username to search authentication event for. */
    @Nonnull
    private List<String> storageUserNameAuthenticationFlowIds;

    /** Constructor. */
    @SuppressWarnings("unchecked")
    ExtractStorageAuthenticationEvent() {
        storageUserNameAuthenticationFlowIds = new ArrayList<String>();
        usernames = new ArrayList<String>();
        multiFactorContextLookupStrategy =
                Functions.compose(new ChildContextLookup(MultiFactorAuthenticationContext.class),
                        new ChildContextLookup(AuthenticationContext.class));

    }

    /**
     * Set the lookup strategy to use for the context to evaluate.
     * 
     * @param strategy lookup strategy
     */
    public void setMultiFactorContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, MultiFactorAuthenticationContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        multiFactorContextLookupStrategy =
                Constraint.isNotNull(strategy, "MultiFactorAuthenticationContext lookup strategy cannot be null");
    }

    /**
     * Set the {@link AuthenticationFlowDescriptor} providing usernames to search authentication event for.
     * 
     * @param flows providing usernames to search authentication event for.
     */
    public void setStorageUsernameAuthenticationFlowDescriptors(
            @Nonnull @NonnullElements final Iterable<AuthenticationFlowDescriptor> flows) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        Constraint.isNotNull(flows, "Flow collection cannot be null");
        for (final AuthenticationFlowDescriptor desc : Iterables.filter(flows, Predicates.notNull())) {
            storageUserNameAuthenticationFlowIds.add(desc.getId());
        }

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

        mfaContext = multiFactorContextLookupStrategy.apply(profileRequestContext);
        if (mfaContext == null) {
            log.error("{} No MultiFactorAuthenticationContext found by lookup strategy", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        for (String flowId : storageUserNameAuthenticationFlowIds) {
            AuthenticationResult result = mfaContext.getActiveResults().get(flowId);
            if (result != null && result.getSubject() != null) {
                for (Principal principal : result.getSubject().getPrincipals(UsernamePrincipal.class)) {
                    usernames.add(principal.getName());
                    log.debug("{} resolved username {} from flow {}", getLogPrefix(), principal.getName(), flowId);

                }
            }
        }
        if (usernames.isEmpty()) {
            log.debug("{} No existing mfa usernames available, nothing to do", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        for (String username : usernames) {
            AuthenticationEvent event = authenticationEventCache.locate(username);
            if (event != null) {
                log.debug(
                        "{} Authentication event located {} for user {}, setting it to storage authentication context",
                        getLogPrefix(), event.serialize(), username);
                StorageAuthenticationContext storageAuthenticationContext =
                        authenticationContext.getSubcontext(StorageAuthenticationContext.class, true);
                storageAuthenticationContext.setAuthenticationEvent(event);
                storageAuthenticationContext.setUsername(username);
                return;
            }
        }
        log.debug("{} no user credentials, authentication event not available", getLogPrefix());
        ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
        return;
    }

}
