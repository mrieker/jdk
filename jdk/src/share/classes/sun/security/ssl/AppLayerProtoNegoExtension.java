/*
 * Copyright (c) 2006, 2012, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package sun.security.ssl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.net.ssl.SSLProtocolException;

/*
 * Application Layer Protocol Negotiation
 * RFC 7301
 */
final class AppLayerProtoNegoExtension extends HelloExtension {
    private int extlength;
    private List<byte[]> alpnbytes;
    private List<String> alpnstrings;

    // constructor for ServerHello
    AppLayerProtoNegoExtension ()
    {
        super (ExtensionType.EXT_APP_LAYER_PROTO_NEGO);
        alpnbytes   = Collections.<byte[]>emptyList ();
        alpnstrings = Collections.<String>emptyList ();
        extlength   = 6;
    }

    // constructor for ClientHello
    AppLayerProtoNegoExtension (List<String> alpns)
    {
        super (ExtensionType.EXT_APP_LAYER_PROTO_NEGO);
        alpnbytes   = new ArrayList<> (alpns.size ());
        alpnstrings = new ArrayList<> (alpns);
        extlength   = 6;
        for (String alpn : alpns) {
            byte[] strbytes = alpn.getBytes ();
            alpnbytes.add (strbytes);
            extlength += strbytes.length + 1;
        }
    }

    // constructor for ServerHello for parsing SNI extension
    AppLayerProtoNegoExtension (HandshakeInStream s, int extlen)
            throws IOException
    {
        super(ExtensionType.EXT_APP_LAYER_PROTO_NEGO);

        if (extlen < 2) throw new SSLProtocolException ("bad extension length");

        int totalen = s.getInt16 ();
        if (totalen > extlen - 2) throw new SSLProtocolException ("bad total length");

        extlength   = 6;
        alpnbytes   = new LinkedList<> ();
        alpnstrings = new LinkedList<> ();
        while (totalen > 0) {
            byte[] strbytes = s.getBytes8 ();
            totalen -= strbytes.length + 1;
            if (totalen < 0) throw new SSLProtocolException ("name runs off end");
            alpnbytes.add   (strbytes);
            alpnstrings.add (new String (strbytes));
            extlength += strbytes.length + 1;
        }
    }

    List<String> getStrings ()
    {
        return new ArrayList<String> (alpnstrings);
    }

    // length of the extension including type and length fields
    @Override
    int length ()
    {
        return extlength;
    }

    @Override
    void send (HandshakeOutStream s)
            throws IOException
    {
        s.putInt16 (type.id);
        s.putInt16 (extlength - 4);
        s.putInt16 (extlength - 6);
        for (byte[] alpn : alpnbytes) {
            s.putBytes8 (alpn);
        }
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder ();
        sb.append ("Extension ALPN");
        for (String alpn : alpnstrings) {
            sb.append (" [");
            sb.append (alpn);
            sb.append (']');
        }
        return sb.toString ();
    }
}
