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

package fi.csc.idp.authn.storage;

import net.shibboleth.utilities.java.support.annotation.Duration;

/**
 * Class implementing limits for reusing storage authentication results. There are three different limits of which
 * failing any will invalidate the authentication.
 */
public class AuthenticationEventRelyingPartyLimits {

    /** Relying party the settings target. */
    private String relyingParty = "";

    /** Max age acceptable in s for the authentication. 0 means infinite. */
    @Duration
    private long authenticationMaxAge = 0;

    /**
     * Max time since last use of event for it to be still acceptable i.e. the rolling window effect. 0 means infinite.
     */
    @Duration
    private long lastAppliedMaxAge = 0;

    /** Max times for stored event to be successfully used to login. 0 means infinite. */
    @Duration
    private int appliedTimesMax = 0;

    /**
     * Get relying party the settings target.
     * 
     * @return relying party the settings target.
     */
    public String getRelyingPartyId() {
        return relyingParty;
    }

    /**
     * Set relying party the settings target.
     * 
     * @param rp relying party the settings target
     */
    // TODO: check for nonnull and nonempty
    public void setRelyingPartyId(String rp) {
        this.relyingParty = rp;
    }

    /**
     * Get max age acceptable in s for the authentication. 0 means infinite.
     * 
     * @return max age acceptable in s for the authentication. 0 means infinite.
     */
    @Duration
    public long getAuthenticationMaxAge() {
        return authenticationMaxAge;
    }

    /**
     * Set Max age acceptable in s for the authentication. 0 means infinite.
     * 
     * @param maxAge max age acceptable in s for the authentication. 0 means infinite.
     */
    public void setAuthenticationMaxAge(@Duration long maxAge) {
        this.authenticationMaxAge = maxAge;
    }

    /**
     * Get max time since last use of event for it to be still acceptable i.e. the rolling window effect. 0 means
     * infinite.
     * 
     * @return max time since last use of event for it to be still acceptable i.e. the rolling window effect. 0 means
     *         infinite.
     */
    @Duration
    public long getLastAppliedMaxAge() {
        return lastAppliedMaxAge;
    }

    /**
     * Set max time since last use of event for it to be still acceptable i.e. the rolling window effect. 0 means
     * infinite.
     * 
     * @param maxAge max time since last use of event for it to be still acceptable i.e. the rolling window effect. 0
     *            means infinite
     */
    public void setLastAppliedMaxAge(@Duration long maxAge) {
        this.lastAppliedMaxAge = maxAge;
    }

    /**
     * Get max times for stored event to be successfully used to login. 0 means infinite..
     * 
     * @return max times for stored event to be successfully used to login. 0 means infinite..
     */
    public int getAppliedTimesMax() {
        return appliedTimesMax;
    }

    /**
     * Set max times for stored event to be successfully used to login. 0 means infinite..
     * 
     * @param max times for stored event to be successfully used to login. 0 means infinite..
     */
    public void setAppliedTimesMax(int max) {
        this.appliedTimesMax = max;
    }
}
