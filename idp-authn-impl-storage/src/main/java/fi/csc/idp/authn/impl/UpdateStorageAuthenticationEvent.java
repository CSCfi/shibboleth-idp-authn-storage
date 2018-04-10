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
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.csc.idp.authn.context.StorageAuthenticationContext;
import fi.csc.idp.authn.storage.AuthenticationEventCache;

@SuppressWarnings("rawtypes")
public class UpdateStorageAuthenticationEvent extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(UpdateStorageAuthenticationEvent.class);

    /** Storage Authentication Event to evaluate. */
    @Nullable
    private StorageAuthenticationContext storageAuthenticationCtx;

    /** Authentication event cache instance to use. */
    @NonnullAfterInit
    private AuthenticationEventCache authenticationEventCache;

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
    @SuppressWarnings("unchecked")
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
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

        storageAuthenticationCtx.getAuthenticationEvent().apply();
        authenticationEventCache.set(storageAuthenticationCtx.getUsername(),
                storageAuthenticationCtx.getAuthenticationEvent());
    }

}