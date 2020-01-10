
package javax.net.ssl;

import java.util.List;

// called during handshaking by SSLEngine on server
// to negotiate an application layer protocol
// according to RFC 7301

// always called if enabled by SSLEngine.setALPNExtensionListener()
//  if client supplied alpn extension,
//    gets called with alpns=list supplied by client
//  otherwise, gets called with alpn=null
// return:
//  null: don't send any alpn reply message
//  else: reply with selected alpn from alpns

public interface ALPNExtensionListener {
    List<String> alpnChoose (List<String> alpns);
}
