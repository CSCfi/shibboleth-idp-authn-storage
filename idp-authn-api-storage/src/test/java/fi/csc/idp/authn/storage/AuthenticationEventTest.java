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

import java.text.ParseException;
import java.util.Date;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class AuthenticationEventTest {

    String eventId = "1";

    String subject = "foo";

    String issuer = "bar";

    String relyingParty2 = "rp2";

    Date authTime = new Date();

    AuthenticationEvent event;

    @BeforeMethod
    public void setup() {
        event = new AuthenticationEvent(eventId, subject, issuer, authTime.getTime());
    }

    @Test
    public void testCreationSuccess() throws ParseException, net.minidev.json.parser.ParseException {
        // and parsing back
        event = AuthenticationEvent.parse(event.serialize());
        Assert.assertEquals(event.getID(), eventId);
        Assert.assertEquals(event.getSubject(), subject);
        Assert.assertEquals(event.getIssuer(), issuer);
        Assert.assertEquals(event.getAuthTime(), authTime.getTime());
        Assert.assertEquals(event.getAppliedCount(), 0);
        Assert.assertEquals(event.getAppliedTime(), authTime.getTime());
        Assert.assertNotNull(event.getIssuedAt());

    }

    @Test
    public void testApply() {
        // and parsing back
        long ts = System.currentTimeMillis();
        event.apply();
        Assert.assertTrue(event.getAppliedTime() >= ts);
        ts = event.getAppliedTime();
        Assert.assertEquals(event.getAppliedCount(), 1);
        event.apply();
        Assert.assertTrue(event.getAppliedTime() >= ts);
        Assert.assertEquals(event.getAppliedCount(), 2);
    }

}