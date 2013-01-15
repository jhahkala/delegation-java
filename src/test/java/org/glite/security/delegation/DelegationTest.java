package org.glite.security.delegation;

import java.security.cert.X509Certificate;

import org.glite.security.delegation.impl.GliteDelegation;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.PEMCredential;

import junit.framework.TestCase;

public class DelegationTest extends TestCase {

    public void testDelegation() throws Exception {
        
        String proxyfile = "src/test/certs/trusted_client.proxy.grid_proxy";
        GrDProxyDlgeeOptions opts = new GrDProxyDlgeeOptions();
        opts.setDlgeeKeySize(2048);
        opts.setDlgeeStorage("target");
        opts.setDlgeeStorageFactory("org.glite.security.delegation.storage.GrDPStorageFilesystemFactory");

        GliteDelegation delegation = new GliteDelegation(opts);
        X509Credential credential = new PEMCredential(proxyfile, (char[]) null);

        X509Certificate[] certChain = credential.getCertificateChain();

        String req = delegation.getProxyReq("testID", certChain);
        System.out.println(req);
        
        GrDProxyDlgorOptions dopts = new GrDProxyDlgorOptions();
        dopts.setDlgorCertFile(proxyfile);
        
        DelegationHandler handler = new DelegationHandler(req, "testID", dopts);
        String certString = handler.getPEMProxyCertificate();
        System.out.println(certString);
        
    }

}
