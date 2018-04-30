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

package fi.csc.idp.authn.storage;

import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import java.text.ParseException;

/** Class representing authentication event stored to event cache. */
public class AuthenticationEvent {

    /** Unique identifier for the authentication event. */
    public static final String KEY_AE_ID = "jti";

    /** Issuer of the event. */
    public static final String KEY_ISSUER = "iss";

    /** User principal representing authenticated user. */
    public static final String KEY_USER_PRINCIPAL = "sub";

    /** Issue time of the authentication instance. */
    public static final String KEY_ISSUED_AT = "iat";

    /** Authentication time of the performed authentication instance. */
    public static final String KEY_AUTH_TIME = "auth_time";

    /** Time when this instance was last time successfully reused. */
    public static final String KEY_APPLIED_TIME = "applied_time";

    /** Number of times this instance has been successfully reused. */
    public static final String KEY_APPLIED_COUNT = "applied_count";

    /** Claims set for the authentication event claim. */
    protected JSONObject authenticationEventObject;

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AuthenticationEvent.class);

    /**
     * Constructor for creating a new authentication event.
     * 
     * @param eventId unique id for the event. Must not be NULL.
     * @param subject the subject authenticated. Must not be NULL.
     * @param issuer the idp/op which has authenticated the user. Must not be NULL.
     * @param authTime the authentication time of the user. Must not be NULL.
     */
    public AuthenticationEvent(@Nonnull String eventId, @Nonnull String subject, @Nonnull String issuer,
            @Nonnull Long authTime) {
        if (eventId == null || subject == null || issuer == null || authTime == null) {
            throw new RuntimeException("Invalid parameters, programming error");
        }
        authenticationEventObject = new JSONObject();
        authenticationEventObject.put(KEY_AE_ID, eventId);
        authenticationEventObject.put(KEY_USER_PRINCIPAL, subject);
        authenticationEventObject.put(KEY_ISSUER, issuer);
        authenticationEventObject.put(KEY_AUTH_TIME, authTime);
        authenticationEventObject.put(KEY_ISSUED_AT, System.currentTimeMillis());
        authenticationEventObject.put(KEY_APPLIED_TIME, authTime);
        authenticationEventObject.put(KEY_APPLIED_COUNT, 0);
    }

    /**
     * Constructor for parsers.
     * 
     * @param authenticationEvent claims set for authentication event.
     */
    private AuthenticationEvent(JSONObject authenticationEvent) {
        authenticationEventObject = authenticationEvent;
    }

    /**
     * Helper to verify parsed claims are what is expected.
     * 
     * @param aeClaimsSet authentication event claims set Must not be NULL.
     * @throws ParseException if claims set is not expected one.
     */
    private static void verifyParsedClaims(@Nonnull JSONObject aeClaimsSet) throws ParseException {
        if (aeClaimsSet.get(KEY_AE_ID) == null) {
            throw new ParseException("claim jti must exist and not be null", 0);
        }
        if (aeClaimsSet.get(KEY_ISSUER) == null) {
            throw new ParseException("claim iss must exist and not be null", 0);
        }
        if (aeClaimsSet.get(KEY_USER_PRINCIPAL) == null) {
            throw new ParseException("claim sub must exist and not be null", 0);
        }
        if (aeClaimsSet.getAsNumber(KEY_AUTH_TIME) == null) {
            throw new ParseException("claim auth_time must exist and not be null", 0);
        }
        if (aeClaimsSet.getAsNumber(KEY_ISSUED_AT) == null) {
            throw new ParseException("claim iat must exist and not be null", 0);
        }
        if (aeClaimsSet.getAsNumber(KEY_APPLIED_TIME) == null) {
            throw new ParseException("claim applied_time must exist and not be null", 0);
        }
        if (aeClaimsSet.getAsNumber(KEY_APPLIED_COUNT) == null) {
            throw new ParseException("claim applied_count must exist and not be null", 0);
        }
    }

    /**
     * Parses authentication event from string (JSON).
     * 
     * @param aeCodeClaimsSet JSON String representation of the code
     * @return AuthenticationEvent instance if parsing is successful.
     * @throws ParseException if parsing fails for example due to incompatible types.
     * @throws net.minidev.json.parser.ParseException
     */
    public static AuthenticationEvent parse(String aeCodeClaimsSet)
            throws ParseException, net.minidev.json.parser.ParseException {
        JSONObject object = (JSONObject) new JSONParser(JSONParser.MODE_STRICTEST).parse(aeCodeClaimsSet);
        // Throws exception if parsing result is not expected one.
        verifyParsedClaims(object);
        return new AuthenticationEvent(object);
    }

    /**
     * Serialize the authentication event as JSON String.
     * 
     * @return authentication event as JSON String
     */
    public String serialize() {
        return authenticationEventObject.toJSONString();
    }

    /**
     * Get the id of the authentication event.
     * 
     * @return id of the authentication event
     */
    @Nonnull
    public String getID() {
        return authenticationEventObject.getAsString(KEY_AE_ID);
    }

    /**
     * Get subject of the authentication event.
     * 
     * @return subject of the authentication event
     */
    @Nonnull
    public String getSubject() {
        return authenticationEventObject.getAsString(KEY_USER_PRINCIPAL);
    }

    /**
     * Get issuer of the authentication event.
     * 
     * @return issuer of the authentication event
     */
    @Nonnull
    public String getIssuer() {
        return authenticationEventObject.getAsString(KEY_ISSUER);
    }

    /**
     * Get authentication time of the authentication event.
     * 
     * @return authentication of the authentication event
     */
    @Nonnull
    public long getAuthTime() {
        return authenticationEventObject.getAsNumber(KEY_AUTH_TIME).longValue();
    }

    /**
     * Get applied time of the authentication event.
     * 
     * @return applied of the authentication event
     */
    @Nonnull
    public long getAppliedTime() {
        return authenticationEventObject.getAsNumber(KEY_APPLIED_TIME).longValue();
    }

    /**
     * Get applied count of the authentication event.
     * 
     * @return applied count of the authentication event
     */
    @Nonnull
    public int getAppliedCount() {
        return authenticationEventObject.getAsNumber(KEY_APPLIED_COUNT).intValue();
    }

    /**
     * Get issued at of the authentication event.
     * 
     * @return issued at of the authentication event
     */
    @Nonnull
    public long getIssuedAt() {
        return authenticationEventObject.getAsNumber(KEY_ISSUED_AT).longValue();
    }

    /**
     * Update event for current apply time.
     */
    public void apply() {
        authenticationEventObject.put(KEY_APPLIED_TIME, System.currentTimeMillis());
        authenticationEventObject.put(KEY_APPLIED_COUNT,
                authenticationEventObject.getAsNumber(KEY_APPLIED_COUNT).intValue() + 1);

    }

}
