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

import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import fi.csc.idp.authn.context.StorageAuthenticationContext;
import fi.csc.idp.authn.storage.AuthenticationEventRelyingPartyLimits;

/** Action verifying the authentication event passes the requirements. */
@SuppressWarnings("rawtypes")
public class VerifyStorageAuthenticationEvent extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(VerifyStorageAuthenticationEvent.class);

    /** Relying party context to get rp id. */
    private RelyingPartyContext relyingPartyCtx;

    /** Storage Authentication Event to evaluate. */
    @Nullable
    private StorageAuthenticationContext storageAuthenticationCtx;

    /** Relying party context lookup strategy. */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** default rp limits. */
    @NonnullAfterInit
    private AuthenticationEventRelyingPartyLimits defaultRPLimits;

    /** rp limits. */
    @Nullable
    private List<AuthenticationEventRelyingPartyLimits> rpLimits;

    VerifyStorageAuthenticationEvent() {
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
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

    public void setDefaultLimits(@Nonnull AuthenticationEventRelyingPartyLimits defaultLimits) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        Constraint.isNotNull(defaultLimits, "Default limits cannot be null");
        defaultRPLimits = defaultLimits;
    }

    public void setRelyingPartyLimits(@Nonnull List<AuthenticationEventRelyingPartyLimits> limits) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        Constraint.isNotNull(limits, "RP limits cannot be null");
        rpLimits = limits;
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        Constraint.isNotNull(defaultRPLimits, "default limits cannot be null");
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }
        relyingPartyCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (relyingPartyCtx == null) {
            log.error("{} No relying party context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        storageAuthenticationCtx = authenticationContext.getSubcontext(StorageAuthenticationContext.class, false);
        if (storageAuthenticationCtx == null) {
            log.debug("{} No StorageAuthenticationContext available within authentication context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_AUTHN_CTX);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        // See if the event is revoked
        if (storageAuthenticationCtx.getAuthenticationEventNotBefore() > storageAuthenticationCtx
                .getAuthenticationEvent().getIssuedAt()) {
            log.debug("{} Authentication event iat {} is not passing for not before {}", getLogPrefix(),
                    storageAuthenticationCtx.getAuthenticationEvent().getIssuedAt(),
                    storageAuthenticationCtx.getAuthenticationEventNotBefore());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
            return;
        }

        // Use either global or rp specific limits
        AuthenticationEventRelyingPartyLimits aeLimits = defaultRPLimits;
        String rpId = relyingPartyCtx.getRelyingPartyId();
        if (rpId != null && rpLimits != null) {
            for (AuthenticationEventRelyingPartyLimits limits : rpLimits) {
                if (rpId.equals(limits.getRelyingPartyId())) {
                    aeLimits = limits;
                    break;
                }
            }
        }

        // Check authentication max age
        if (aeLimits.getAuthenticationMaxAge() != 0) {
            long dueTime = storageAuthenticationCtx.getAuthenticationEvent().getAuthTime()
                    + (aeLimits.getAuthenticationMaxAge());
            if (dueTime < System.currentTimeMillis()) {
                log.debug("{} Authentication event authentication time {} is not passing for max age {}ms",
                        getLogPrefix(), storageAuthenticationCtx.getAuthenticationEvent().getAuthTime(),
                        aeLimits.getAuthenticationMaxAge());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
                return;
            }
        }

        // Check rolling window
        if (aeLimits.getLastAppliedMaxAge() != 0) {
            long dueTime = storageAuthenticationCtx.getAuthenticationEvent().getAppliedTime()
                    + (aeLimits.getLastAppliedMaxAge());
            if (dueTime < System.currentTimeMillis()) {
                log.debug("{} Authentication event last applied time {} is not passing for max age {}ms",
                        getLogPrefix(), storageAuthenticationCtx.getAuthenticationEvent().getAppliedTime(),
                        aeLimits.getLastAppliedMaxAge());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
                return;
            }
        }

        // Check for max times used
        if (aeLimits.getAppliedTimesMax() != 0) {
            if (aeLimits.getAppliedTimesMax() <= storageAuthenticationCtx.getAuthenticationEvent().getAppliedCount()) {
                log.debug("{} Authentication event applied count {} is not passing for max value {}", getLogPrefix(),
                        storageAuthenticationCtx.getAuthenticationEvent().getAppliedCount(),
                        aeLimits.getAppliedTimesMax());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
                return;
            }
        }
    }

}