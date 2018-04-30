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

package fi.csc.idp.authn.context;

import javax.annotation.Nullable;

import org.opensaml.messaging.context.BaseContext;

import fi.csc.idp.authn.storage.AuthenticationEvent;

/** Storage Authentication Context. Stores authentication event. */
public class StorageAuthenticationContext extends BaseContext {

    /** Authentication event located from storage. */
    private AuthenticationEvent authenticationEvent;

    /** Key/Username used for locating the event. */
    private String username;

    /**
     * Time in milliseconds since the epoch for events issued before not be accepted. 0 means there is no value to be
     * checked.
     */
    private long authenticationEventNotBefore = 0;

    /**
     * Get time in milliseconds since the epoch for events issued before not be accepted. 0 means there is no value to
     * be checked.
     * 
     * @return time in milliseconds since the epoch for events issued before not be accepted. 0 means there is no value
     *         to be checked.
     */
    public long getAuthenticationEventNotBefore() {
        return authenticationEventNotBefore;
    }

    /**
     * Set time in milliseconds since the epoch for events issued before not be accepted. 0 means there is no value to
     * be checked.
     * 
     * @param tsNotBefore time in milliseconds since the epoch for events issued before not be accepted. 0 means there
     *            is no value to be checked.
     */
    public void setAuthenticationEventNotBefore(@Nullable String tsNotBefore) {
        if (tsNotBefore != null) {
            // Will cause MFA script to fail (NumberformatException) if called with bad argument
            authenticationEventNotBefore = Long.parseLong(tsNotBefore);
        } else {
            authenticationEventNotBefore = 0;
        }
    }

    /**
     * Get key/username used for locating the event.
     * 
     * @return Key/Username used for locating the event.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Set key/username used for locating the event.
     * 
     * @param value Key/Username used for locating the event.
     */
    public void setUsername(String value) {
        username = value;
    }

    /**
     * Get authentication event located from storage.
     * 
     * @return authentication event located from storage
     */
    public AuthenticationEvent getAuthenticationEvent() {
        return authenticationEvent;
    }

    /**
     * Set authentication event located from storage.
     * 
     * @param event authentication event located from storage
     */
    public void setAuthenticationEvent(AuthenticationEvent event) {
        authenticationEvent = event;
    }

}
