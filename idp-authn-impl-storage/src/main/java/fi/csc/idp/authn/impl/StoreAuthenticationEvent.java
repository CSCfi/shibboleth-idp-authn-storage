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
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import org.opensaml.profile.action.ActionSupport;
import net.shibboleth.idp.profile.context.navigate.ResponderIdLookupFunction;
import net.shibboleth.idp.session.context.navigate.CanonicalUsernameLookupStrategy;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.security.IdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.security.SecureRandomIdentifierGenerationStrategy;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;

import fi.csc.idp.authn.context.StorageAuthenticationContext;
import fi.csc.idp.authn.storage.AuthenticationEvent;
import fi.csc.idp.authn.storage.AuthenticationEventCache;

/** Action storing authentication event for user. */
@SuppressWarnings({"rawtypes"})
public class StoreAuthenticationEvent extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(StoreAuthenticationEvent.class);

    /** Strategy used to locate the identity of the issuer associated with the attribute resolution. */
    @Nullable
    private Function<ProfileRequestContext, String> issuerLookupStrategy;

    /** Authentication event cache instance to use. */
    @NonnullAfterInit
    private AuthenticationEventCache authenticationEventCache;

    /** Username to store the authentication event for. */
    private String username;

    /** The generator to use. */
    @Nullable
    private IdentifierGenerationStrategy idGenerator;

    /** Strategy used to locate the {@link IdentifierGenerationStrategy} to use. */
    @Nonnull
    private Function<ProfileRequestContext, IdentifierGenerationStrategy> idGeneratorLookupStrategy;

    /** Lookup strategy for username to search authentication event for. */
    @Nonnull
    private Function<ProfileRequestContext, String> usernameLookupStrategy;

    /** Storage Authentication Event to evaluate. */
    @Nullable
    private StorageAuthenticationContext storageAuthenticationCtx;

    /** Constructor. */
    StoreAuthenticationEvent() {
        usernameLookupStrategy = new CanonicalUsernameLookupStrategy();
        issuerLookupStrategy = new ResponderIdLookupFunction();
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
     * Set the strategy used to lookup the issuer for this authentication event.
     * 
     * @param strategy lookup strategy
     */
    public void setIssuerLookupStrategy(@Nullable final Function<ProfileRequestContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        issuerLookupStrategy = strategy;
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

        storageAuthenticationCtx = authenticationContext.getSubcontext(StorageAuthenticationContext.class, false);
        if (storageAuthenticationCtx == null) {
            log.debug("{} No StorageAuthenticationContext available within authentication context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_AUTHN_CTX);
            return false;
        }
        username = storageAuthenticationCtx.getUsername();
        if (username == null) {
            log.warn("{} No existing canicalized username available, nothing to do", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return false;
        }
        idGenerator = idGeneratorLookupStrategy.apply(profileRequestContext);
        if (idGenerator == null) {
            log.error("{} No identifier generation strategy", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        log.debug("{} Storing authentication event for user {}", getLogPrefix(), username);
        AuthenticationEvent event = new AuthenticationEvent(idGenerator.generateIdentifier(), username,
                issuerLookupStrategy.apply(profileRequestContext), System.currentTimeMillis());
        authenticationEventCache.set(username, event);
        return;
    }

}
