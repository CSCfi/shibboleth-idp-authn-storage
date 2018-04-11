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
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.MultiFactorAuthenticationContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import org.opensaml.profile.action.ActionSupport;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.ResponderIdLookupFunction;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.security.IdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.security.SecureRandomIdentifierGenerationStrategy;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.google.common.base.Predicates;
import com.google.common.collect.Iterables;

import fi.csc.idp.authn.storage.AuthenticationEvent;
import fi.csc.idp.authn.storage.AuthenticationEventCache;

/** Action storing authentication event for user. */
@SuppressWarnings({"rawtypes"})
public class StoreAuthenticationEvent extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(StoreAuthenticationEvent.class);

    /** Relying party context to get rp id. */
    private RelyingPartyContext relyingPartyCtx;

    /** Strategy used to locate the identity of the issuer associated with the attribute resolution. */
    @Nullable
    private Function<ProfileRequestContext, String> issuerLookupStrategy;

    /** Relying party context lookup strategy. */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** Authentication event cache instance to use. */
    @NonnullAfterInit
    private AuthenticationEventCache authenticationEventCache;

    /** Lookup function for the context to evaluate. */
    @Nonnull
    private Function<ProfileRequestContext, MultiFactorAuthenticationContext> multiFactorContextLookupStrategy;

    /** A subordinate {@link MultiFactorAuthenticationContext}, if any. */
    @Nullable
    private MultiFactorAuthenticationContext mfaContext;

    /** Username to store the authentication event for. */
    private String userName;

    /** Flows that provide username to set authentication event for. */
    @Nonnull
    private List<String> storageUserNameAuthenticationFlowIds;

    /** Flows that may provide authentication event. */
    @Nonnull
    private List<String> storageAuthenticationEventAuthenticationFlows;

    /** Authentication result to store. */
    @Nonnull
    private AuthenticationResult result;

    /** The generator to use. */
    @Nullable
    private IdentifierGenerationStrategy idGenerator;

    /** Strategy used to locate the {@link IdentifierGenerationStrategy} to use. */
    @Nonnull
    private Function<ProfileRequestContext, IdentifierGenerationStrategy> idGeneratorLookupStrategy;

    /** Constructor. */
    @SuppressWarnings("unchecked")
    StoreAuthenticationEvent() {
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
        issuerLookupStrategy = new ResponderIdLookupFunction();
        storageUserNameAuthenticationFlowIds = new ArrayList<String>();
        storageAuthenticationEventAuthenticationFlows = new ArrayList<String>();
        multiFactorContextLookupStrategy =
                Functions.compose(new ChildContextLookup(MultiFactorAuthenticationContext.class),
                        new ChildContextLookup(AuthenticationContext.class));
        idGeneratorLookupStrategy = new Function<ProfileRequestContext, IdentifierGenerationStrategy>() {
            public IdentifierGenerationStrategy apply(ProfileRequestContext input) {
                return new SecureRandomIdentifierGenerationStrategy();
            }
        };
    }

    /**
     * Set the strategy used to locate the {@link IdentifierGenerationStrategy} to use.
     * 
     * @param strategy lookup strategy
     */
    public void setIdentifierGeneratorLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, IdentifierGenerationStrategy> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        idGeneratorLookupStrategy =
                Constraint.isNotNull(strategy, "IdentifierGenerationStrategy lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to lookup the issuer for this attribute resolution.
     * 
     * @param strategy lookup strategy
     */
    public void setIssuerLookupStrategy(@Nullable final Function<ProfileRequestContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        issuerLookupStrategy = strategy;
    }

    /**
     * Set the relying party context lookup strategy.
     * 
     * @param strategy lookup strategy
     */
    public void setRelyingPartyContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, RelyingPartyContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        relyingPartyContextLookupStrategy =
                Constraint.isNotNull(strategy, "RelyingPartyContext lookup strategy cannot be null");
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
     * Set the {@link AuthenticationFlowDescriptor} providing usernames to set authentication event for.
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
     * Set the {@link AuthenticationFlowDescriptor} providing flows which results may be stored as authentication event.
     * 
     * @param flows providing results to to store as authentication event.
     */
    public void setStorageAuthenticationEventAuthenticationFlowDescriptors(
            @Nonnull @NonnullElements final Iterable<AuthenticationFlowDescriptor> flows) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        Constraint.isNotNull(flows, "Flow collection cannot be null");
        for (final AuthenticationFlowDescriptor desc : Iterables.filter(flows, Predicates.notNull())) {
            storageAuthenticationEventAuthenticationFlows.add(desc.getId());
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

        relyingPartyCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (relyingPartyCtx == null) {
            log.error("{} No relying party context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        mfaContext = multiFactorContextLookupStrategy.apply(profileRequestContext);
        if (mfaContext == null) {
            log.error("{} No MultiFactorAuthenticationContext found by lookup strategy", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        idGenerator = idGeneratorLookupStrategy.apply(profileRequestContext);
        if (idGenerator == null) {
            log.error("{} No identifier generation strategy", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        outer: for (String flowId : storageUserNameAuthenticationFlowIds) {
            AuthenticationResult result = mfaContext.getActiveResults().get(flowId);
            if (result != null && result.getSubject() != null) {
                for (Principal principal : result.getSubject().getPrincipals(UsernamePrincipal.class)) {
                    userName = principal.getName();
                    break outer;
                }
            }
        }
        if (userName == null) {
            log.debug("{} username not solved, nothing to do", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_SUBJECT);
            return false;
        }
        for (String flowId : storageAuthenticationEventAuthenticationFlows) {
            result = mfaContext.getActiveResults().get(flowId);
            if (result != null) {
                return true;
            }
        }
        log.debug("{} result not solved, nothing to do", getLogPrefix());
        ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
        return false;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        log.debug("{} Storing authentication event for user {}", getLogPrefix(), userName);
        AuthenticationEvent event = new AuthenticationEvent(idGenerator.generateIdentifier(), userName,
                issuerLookupStrategy.apply(profileRequestContext), result.getAuthenticationInstant());
        authenticationEventCache.set(userName, event);
        return;
    }

}
