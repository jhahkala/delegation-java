package org.glite.security.delegation;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.glite.security.delegation.impl.GliteDelegation;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.impl.PEMCredential;

import junit.framework.TestCase;

public class DelegationTest extends TestCase {

    public void testDelegation() throws FileNotFoundException, IOException, DelegationException, KeyStoreException,
            CertificateException {
        GrDProxyDlgeeOptions opts = new GrDProxyDlgeeOptions();
        opts.setDlgeeKeySize(2048);
        opts.setDlgeeProxyFile("src/test/certs/trusted_client.proxy.grid_proxy");
        opts.setDlgeeStorage("target");
        opts.setDlgeeStorageFactory("org.glite.security.delegation.storage.GrDPStorageFilesystemFactory");
        opts.setDlgeeStorage("target");

        GliteDelegation delegation = new GliteDelegation(opts);
        X509Credential credential = new PEMCredential("src/test/certs/trusted_client.proxy.grid_proxy", (char[]) null);

        X509Certificate[] certChain = credential.getCertificateChain();

        String req = delegation.getProxyReq("testID", certChain);
        System.out.println(req);
    }

}
