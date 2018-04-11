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

import java.io.IOException;
import java.text.ParseException;
import java.util.concurrent.locks.ReentrantLock;

import javax.annotation.Nonnull;
import net.shibboleth.utilities.java.support.annotation.Duration;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.annotation.constraint.Positive;
import net.shibboleth.utilities.java.support.annotation.constraint.ThreadSafeAfterInit;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.apache.commons.codec.digest.DigestUtils;
import org.opensaml.storage.StorageCapabilities;
import org.opensaml.storage.StorageCapabilitiesEx;
import org.opensaml.storage.StorageRecord;
import org.opensaml.storage.StorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages authentication events in client-side and possibly back-side storage.
 * <p>
 * This class is thread-safe and uses a lock to prevent race conditions within the underlying store (lacking an atomic
 * "check and insert" operation).
 * </p>
 */
@ThreadSafeAfterInit
public class AuthenticationEventCache extends AbstractIdentifiableInitializableComponent {

    /** Logger. */
    private final Logger log = LoggerFactory.getLogger(AuthenticationEventCache.class);

    /** Lock to control access to storage. */
    private static ReentrantLock lock = new ReentrantLock();

    /** cache context for reference values . */
    private final static String REF_CTX = AuthenticationEventCache.class.getName() + "_REF_CTX";

    /** cache context for authentication events . */
    private final static String EVENT_CTX = AuthenticationEventCache.class.getName() + "_EVENT_CTX";

    /** Reference storage for the authentication cache. */
    private StorageService referenceStorage;

    /** Event storage for the authentication cache. By default Event store is Reference store. */
    private StorageService eventStorage;

    /** Salt for hashing user to key. */
    @NonnullAfterInit
    private String userSalt;

    /** Lifetime of revocation entry. Default value: 7 days */
    @Positive
    @Duration
    private long expires;

    /**
     * Constructor.
     */
    public AuthenticationEventCache() {
        expires = 7 * 24 * 60 * 60 * 1000;
    }

    /**
     * Set the revocation entry expiration.
     * 
     * @param entryExpiration lifetime of an refresh token in milliseconds
     */
    @Duration
    public void setEntryExpiration(@Positive @Duration final long entryExpiration) {
        expires = Constraint.isGreaterThan(0, entryExpiration,
                "revocation cache entry expiration must be greater than 0");
    }

    public void setUserSalt(String salt) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        userSalt = Constraint.isNotNull(salt, "User salt cannot be null");
    }

    /**
     * Set the reference store for the cache.
     * 
     * @param storageService reference store to use
     */
    public void setReferenceStorage(@Nonnull final StorageService storageService) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        referenceStorage = Constraint.isNotNull(storageService, "StorageService cannot be null");
        final StorageCapabilities caps = referenceStorage.getCapabilities();
        if (caps instanceof StorageCapabilitiesEx) {
            Constraint.isFalse(((StorageCapabilitiesEx) caps).isServerSide(), "StorageService must be client-side");
        }
    }

    /**
     * Set the Event store for the cache. By default Event store is Reference store.
     * 
     * @param storageService event store to use
     */
    public void setEventStorage(@Nonnull final StorageService storageService) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        eventStorage = Constraint.isNotNull(storageService, "StorageService cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    public void doInitialize() throws ComponentInitializationException {
        if (referenceStorage == null) {
            throw new ComponentInitializationException("Reference StorageService cannot be null");
        }
        if (userSalt == null) {
            throw new ComponentInitializationException("User salt cannot be null");
        }
        // By default Event store is Reference store.
        if (eventStorage == null) {
            eventStorage = referenceStorage;
        }
    }

    @SuppressWarnings("rawtypes")
    public AuthenticationEvent locate(@Nonnull @NotEmpty final String userKey) {
        String key;
        // TODO: replace with salted digest
        key = DigestUtils.sha256Hex(userKey + userSalt);
        log.debug("User {} hashed to {}", userKey, key);
        lock.lock();
        try {
            StorageRecord refEntry = referenceStorage.read(REF_CTX, key);
            if (refEntry != null) {
                StorageRecord eventEntry = eventStorage.read(EVENT_CTX, refEntry.getValue());
                if (eventEntry != null) {
                    try {
                        AuthenticationEvent event = AuthenticationEvent.parse(eventEntry.getValue());
                        return event;
                    } catch (ParseException | net.minidev.json.parser.ParseException e) {
                        log.error("Exception reading/writing to storage service {}", e);
                    }
                }
            }
        } catch (IOException e) {
            log.error("Exception reading/writing to storage service {}", e);
        } finally {
            lock.unlock();
        }
        return null;
    }

    public boolean set(@Nonnull @NotEmpty final String userKey, @Nonnull @NotEmpty final AuthenticationEvent value) {
        String key;
        // TODO: replace with salted digest
        key = DigestUtils.sha256Hex(userKey + userSalt);
        log.debug("User {} hashed to {}", userKey, key);
        lock.lock();
        try {
            boolean success = referenceStorage.create(REF_CTX, key, value.getID(), System.currentTimeMillis() + expires)
                    || referenceStorage.update(REF_CTX, key, value.getID(), System.currentTimeMillis() + expires);
            if (!success) {
                log.debug("Not able to create event reference");
                return false;
            }
            success = eventStorage.create(EVENT_CTX, value.getID(), value.serialize(),
                    System.currentTimeMillis() + expires)
                    || eventStorage.update(EVENT_CTX, value.getID(), value.serialize(),
                            System.currentTimeMillis() + expires);
            if (!success) {
                log.debug("Not able to create event ");
                return false;
            }
            return success;
        } catch (IOException e) {
            log.error("Exception reading/writing to storage service, returning {}", e);
            return false;
        } finally {
            lock.unlock();
        }
    }
}