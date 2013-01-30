package org.glite.security.delegation;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.glite.security.delegation.impl.GliteDelegation;
import org.glite.security.delegation.storage.GrDPStorage;
import org.glite.security.delegation.storage.GrDPStorageElement;
import org.glite.security.delegation.storage.GrDPStorageFactory;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.PEMCredential;

import junit.framework.TestCase;

public class DelegationTest extends TestCase {

    public void testDelegationWithoutVoms() throws Exception {
        
//        Logger LOGGERRoot = Logger.getLogger("org.glite.security");
//        Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %l %x - %m%n");
//        Appender appender = new ConsoleAppender(lay);
//        LOGGERRoot.addAppender(appender);
//        LOGGERRoot.setLevel(Level.DEBUG);

        String proxyfile = "src/test/certs/trusted_client.proxy.grid_proxy";
        String delegationId = "testID";

        // server side request generation
        GrDProxyDlgeeOptions opts = new GrDProxyDlgeeOptions();
        opts.setDlgeeKeySize(2048);
        opts.setDlgeeStorage("target");
        opts.setDlgeeStorageFactory("org.glite.security.delegation.storage.GrDPStorageFilesystemFactory");
        // for testing purposes
        opts.setRequireVomsAttributes(false);

        GliteDelegation delegation = new GliteDelegation(opts);
        X509Credential credential = new PEMCredential(proxyfile, (char[]) null);

        X509Certificate[] certChain = credential.getCertificateChain();

        // first try to remove old delegation in case one exists.
        try {
            delegation.destroy(delegationId, certChain);
        }catch(Exception e){
            // ignore
        }
        
        String req = delegation.getProxyReq(delegationId, certChain);
        
        // client side new proxy signing
        GrDProxyDlgorOptions dopts = new GrDProxyDlgorOptions();
        dopts.setDlgorCertFile(proxyfile);

        DelegationHandler handler = new DelegationHandler(req, delegationId, dopts);
        String certString = handler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, certString, certChain);

        GrDPStorageFactory stgFactory = GrDPX509Util.getGrDPStorageFactory(opts.getDlgeeStorageFactory());
        GrDPStorage storage = stgFactory.createGrDPStorage(opts);
        CertInfoTriple info = new CertInfoTriple(certChain, null, false);
        
        GrDPStorageElement element = storage.findGrDPStorageElement(delegationId, info.dn);
        
        PEMCredential newCredential = new PEMCredential(new ByteArrayInputStream(element.getCertificate().getBytes()), (char[])null);
        
        X509Certificate newChain[] = newCredential.getCertificateChain();
        PrivateKey newKey = newCredential.getKey();
        
//        newChain[0].getPublicKey()
//        ((RSAPrivateKey)newKey).
//        
        // remove delegation in the end
        delegation.destroy(delegationId, certChain);

    }

    public void testDelegationWithVoms() throws Exception {
        
//        Logger LOGGERRoot = Logger.getLogger("org");
//        Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %l %x - %m%n");
//        Appender appender = new ConsoleAppender(lay);
//        LOGGERRoot.addAppender(appender);
//        LOGGERRoot.setLevel(Level.DEBUG);

        String proxyfile = "src/test/certs/trusted_client.voms_proxy";
        String delegationId = "testID";

        // server side request generation
        GrDProxyDlgeeOptions opts = new GrDProxyDlgeeOptions();
        opts.setDlgeeKeySize(2048);
        opts.setDlgeeStorage("target");
        opts.setDlgeeStorageFactory("org.glite.security.delegation.storage.GrDPStorageFilesystemFactory");
        // for testing purposes
        opts.setRequireVomsAttributes(true);
        opts.setVomsCAs("src/test/grid-security/certificates");
        opts.setVomsDir("src/test/grid-security/vomsdir");

        GliteDelegation delegation = new GliteDelegation(opts);
        X509Credential credential = new PEMCredential(proxyfile, (char[]) null);

        X509Certificate[] certChain = credential.getCertificateChain();

        // first try to remove old delegation in case one exists.
        try {
            delegation.destroy(delegationId, certChain);
        }catch(Exception e){
            // ignore
        }
        
        String req = delegation.getProxyReq(delegationId, certChain);
        
        // client side new proxy signing
        GrDProxyDlgorOptions dopts = new GrDProxyDlgorOptions();
        dopts.setDlgorCertFile(proxyfile);

        DelegationHandler handler = new DelegationHandler(req, delegationId, dopts);
        String certString = handler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, certString, certChain);

        // remove delegation in the end
        delegation.destroy(delegationId, certChain);

    }

    public void testDelegationWithVomsNoID() throws Exception {
        
//        Logger LOGGERRoot = Logger.getLogger("org");
//        Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %l %x - %m%n");
//        Appender appender = new ConsoleAppender(lay);
//        LOGGERRoot.addAppender(appender);
//        LOGGERRoot.setLevel(Level.DEBUG);

        String proxyfile = "src/test/certs/trusted_client.voms_proxy";
        String delegationId = null;

        // server side request generation
        GrDProxyDlgeeOptions opts = new GrDProxyDlgeeOptions();
        opts.setDlgeeKeySize(2048);
        opts.setDlgeeStorage("target");
        opts.setDlgeeStorageFactory("org.glite.security.delegation.storage.GrDPStorageFilesystemFactory");
        // for testing purposes
        opts.setRequireVomsAttributes(true);
        opts.setVomsCAs("src/test/grid-security/certificates");
        opts.setVomsDir("src/test/grid-security/vomsdir");

        GliteDelegation delegation = new GliteDelegation(opts);
        X509Credential credential = new PEMCredential(proxyfile, (char[]) null);

        X509Certificate[] certChain = credential.getCertificateChain();

        // first try to remove old delegation in case one exists.
        try {
            delegation.destroy(delegationId, certChain);
        }catch(Exception e){
            // ignore
        }
        
        String req = delegation.getProxyReq(delegationId, certChain);
        
        // client side new proxy signing
        GrDProxyDlgorOptions dopts = new GrDProxyDlgorOptions();
        dopts.setDlgorCertFile(proxyfile);

        DelegationHandler handler = new DelegationHandler(req, delegationId, dopts);
        String certString = handler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, certString, certChain);

        // remove delegation in the end
        delegation.destroy(delegationId, certChain);

    }

}
