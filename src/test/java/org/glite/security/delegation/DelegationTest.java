package org.glite.security.delegation;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;

import org.glite.security.delegation.impl.GliteDelegation;
import org.glite.security.delegation.storage.GrDPStorage;
import org.glite.security.delegation.storage.GrDPStorageElement;
import org.glite.security.delegation.storage.GrDPStorageFactory;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.RevocationParameters.RevocationCheckingOrder;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorListener;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;
import eu.emi.security.authn.x509.impl.PEMCredential;
import eu.emi.security.authn.x509.impl.ValidatorParams;
import eu.emi.security.authn.x509.proxy.ProxyChainInfo;
import eu.emi.security.authn.x509.proxy.ProxyChainType;

import junit.framework.TestCase;

public class DelegationTest extends TestCase {

    public OpensslCertChainValidator getValidator() {
        StoreUpdateListener listener = new StoreUpdateListener() {
            public void loadingNotification(String location, String type, Severity level, Exception cause) {
                if (level != Severity.NOTIFICATION) {
                    System.out.println("Error when creating or using SSL socket. Type " + type + " level: " + level
                            + ((cause == null) ? "" : (" cause: " + cause.getClass() + ":" + cause.getMessage())));
                } else {
                    // log successful (re)loading
                }
            }
        };

        ArrayList<StoreUpdateListener> listenerList = new ArrayList<StoreUpdateListener>();
        listenerList.add(listener);

        RevocationParameters revParam = new RevocationParameters(CrlCheckingMode.REQUIRE, new OCSPParametes(), false,
                RevocationCheckingOrder.CRL_OCSP);

        ValidatorParams validatorParams = new ValidatorParams(revParam, ProxySupport.ALLOW, listenerList);

        String trustStoreLocation = "src/test/grid-security/certificates";

        NamespaceCheckingMode namespaceMode = NamespaceCheckingMode.EUGRIDPMA_AND_GLOBUS;

        long intervalMS = 3600000; // update every hour

        OpensslCertChainValidator validator = new OpensslCertChainValidator(trustStoreLocation, namespaceMode,
                intervalMS, validatorParams);

        ValidationErrorListener validationListener = new ValidationErrorListener() {
            @Override
            public boolean onValidationError(ValidationError error) {
                System.out.println("Error when validating incoming certificate: " + error.getMessage() + " position: "
                        + error.getPosition() + " " + error.getParameters());
                X509Certificate chain[] = error.getChain();
                for (X509Certificate cert : chain) {
                    System.out.println(cert.toString());
                }
                return false;
            }

        };

        validator.addValidationListener(validationListener);
        return validator;

    }

    public void testDelegationWithoutVoms() throws Exception {

        // Logger LOGGERRoot = Logger.getLogger("org.glite.security");
        // Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %l %x - %m%n");
        // Appender appender = new ConsoleAppender(lay);
        // LOGGERRoot.addAppender(appender);
        // LOGGERRoot.setLevel(Level.DEBUG);

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
        } catch (Exception e) {
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

        // get the delegated credentials from the storage
        GrDPStorageFactory stgFactory = GrDPX509Util.getGrDPStorageFactory(opts.getDlgeeStorageFactory());
        GrDPStorage storage = stgFactory.createGrDPStorage(opts);
        CertInfoTriple info = new CertInfoTriple(certChain, null, false);

        GrDPStorageElement element = storage.findGrDPStorageElement(delegationId, info.dn);

        PEMCredential newCredential = new PEMCredential(new ByteArrayInputStream(element.getCertificate().getBytes()),
                (char[]) null);

        RSAKey pubKey = (RSAKey) newCredential.getCertificateChain()[0].getPublicKey();
        RSAPrivateCrtKey newKey = (RSAPrivateCrtKey) newCredential.getKey();

        BigInteger pubModulus = pubKey.getModulus();
        BigInteger privModulus = newKey.getModulus();
        assertEquals("Private key and public key of delegated credentials don't match.", pubModulus, privModulus);

        OpensslCertChainValidator validator = getValidator();
        ValidationResult result = validator.validate(newCredential.getCertificateChain());
        assertTrue(result.isValid());
        
        ProxyChainInfo newProxyInfo = new ProxyChainInfo(newCredential.getCertificateChain());
        assertFalse("New proxy is limited even though it should not be.", newProxyInfo.isLimited());
        assertTrue("New proxy is not legacy proxy even though it should be", newProxyInfo.getProxyType() == ProxyChainType.LEGACY);
        
        // check getting the expiration time
        Calendar expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Original delegation exp time" + expTime.getTime().getTime());
        Calendar compareDate = new GregorianCalendar();
        compareDate.add(Calendar.HOUR, 12);
        assertTrue("Delegated credential expires too late", expTime.before(compareDate));
        compareDate.add(Calendar.SECOND, -3);
        assertTrue("Delegated credential expires too early", expTime.after(compareDate));
        Thread.sleep(1000);

        // test proxy renewal
        String renewReq = delegation.renewProxyReq(delegationId, certChain);
        DelegationHandler renewHandler = new DelegationHandler(renewReq, delegationId, dopts);
        String renewCertString = renewHandler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, renewCertString, certChain);
        expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Renewed delegation exp time" + expTime.getTime().getTime());
        compareDate.add(Calendar.SECOND, 3);
        // System.out.println(compareDate.getTime().getTime());
        // System.out.println("comparison returns: " + expTime.compareTo(compareDate));
        assertTrue("Delegated credential expires too early, renewal failed", expTime.after(compareDate));

        // verify the cache is empty and putting the delegation in again fails
        boolean exception = false;
        try {
            delegation.putProxy(delegationId, renewCertString, certChain);
        } catch (Exception e) {
            exception = true;
        }
        assertTrue("Putting already handled proxy didn't fail like it should", exception);

        //
        // remove delegation in the end
        delegation.destroy(delegationId, certChain);

        // verify the delegation is gone
        element = storage.findGrDPStorageElement(delegationId, info.dn);
        assertNull("Finding deleted proxy form storage didn't fail like it should", element);

    }

    public void testDelegationWithoutVomsTrace() throws Exception {

        // Logger LOGGERRoot = Logger.getLogger("org.glite.security");
        // Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %l %x - %m%n");
        // Appender appender = new ConsoleAppender(lay);
        // LOGGERRoot.addAppender(appender);
        // LOGGERRoot.setLevel(Level.DEBUG);

        String proxyfile = "src/test/certs/trusted_client.proxy.grid_proxy";
        String delegationId = "testID";
        String tracingFrom = "https://from.com/foo";
        String tracingTo = "https://to.com/bar";

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
        } catch (Exception e) {
            // ignore
        }

        String req = delegation.getProxyReq(delegationId, certChain);

        // client side new proxy signing
        GrDProxyDlgorOptions dopts = new GrDProxyDlgorOptions();
        dopts.setDlgorCertFile(proxyfile);
        dopts.setTracingIssuer(tracingFrom);
        dopts.setTracingSubject(tracingTo);

        DelegationHandler handler = new DelegationHandler(req, delegationId, dopts);
        String certString = handler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, certString, certChain);

        // get the delegated credentials from the storage
        GrDPStorageFactory stgFactory = GrDPX509Util.getGrDPStorageFactory(opts.getDlgeeStorageFactory());
        GrDPStorage storage = stgFactory.createGrDPStorage(opts);
        CertInfoTriple info = new CertInfoTriple(certChain, null, false);

        GrDPStorageElement element = storage.findGrDPStorageElement(delegationId, info.dn);

        PEMCredential newCredential = new PEMCredential(new ByteArrayInputStream(element.getCertificate().getBytes()),
                (char[]) null);

        RSAKey pubKey = (RSAKey) newCredential.getCertificateChain()[0].getPublicKey();
        RSAPrivateCrtKey newKey = (RSAPrivateCrtKey) newCredential.getKey();

        BigInteger pubModulus = pubKey.getModulus();
        BigInteger privModulus = newKey.getModulus();
        assertEquals("Private key and public key of delegated credentials don't match.", pubModulus, privModulus);

        OpensslCertChainValidator validator = getValidator();
        ValidationResult result = validator.validate(newCredential.getCertificateChain());
        assertTrue(result.isValid());
        
        ProxyChainInfo newProxyInfo = new ProxyChainInfo(newCredential.getCertificateChain());
        assertFalse("New proxy is limited even though it should not be.", newProxyInfo.isLimited());
        assertTrue("New proxy is not legacy proxy even though it should be", newProxyInfo.getProxyType() == ProxyChainType.LEGACY);
        assertNotNull("Proxy issuer tracing extension does exist even though it was set.", newProxyInfo.getProxyTracingIssuers());
        assertEquals("Proxy issuer tracing extension does not match the set value.", newProxyInfo.getProxyTracingIssuers()[0], tracingFrom);
        assertNotNull("Proxy subject tracing extension does exist even though it was set.", newProxyInfo.getProxyTracingSubjects());
        assertEquals("Proxy subject tracing extension does not match the set value.", newProxyInfo.getProxyTracingSubjects()[0], tracingTo);
        
        // check getting the expiration time
        Calendar expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Original delegation exp time" + expTime.getTime().getTime());
        Calendar compareDate = new GregorianCalendar();
        compareDate.add(Calendar.HOUR, 12);
        assertTrue("Delegated credential expires too late", expTime.before(compareDate));
        compareDate.add(Calendar.SECOND, -3);
        assertTrue("Delegated credential expires too early", expTime.after(compareDate));
        Thread.sleep(1000);

        // test proxy renewal
        String renewReq = delegation.renewProxyReq(delegationId, certChain);
        DelegationHandler renewHandler = new DelegationHandler(renewReq, delegationId, dopts);
        String renewCertString = renewHandler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, renewCertString, certChain);
        expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Renewed delegation exp time" + expTime.getTime().getTime());
        compareDate.add(Calendar.SECOND, 3);
        // System.out.println(compareDate.getTime().getTime());
        // System.out.println("comparison returns: " + expTime.compareTo(compareDate));
        assertTrue("Delegated credential expires too early, renewal failed", expTime.after(compareDate));

        // verify the cache is empty and putting the delegation in again fails
        boolean exception = false;
        try {
            delegation.putProxy(delegationId, renewCertString, certChain);
        } catch (Exception e) {
            exception = true;
        }
        assertTrue("Putting already handled proxy didn't fail like it should", exception);

        //
        // remove delegation in the end
        delegation.destroy(delegationId, certChain);

        // verify the delegation is gone
        element = storage.findGrDPStorageElement(delegationId, info.dn);
        assertNull("Finding deleted proxy form storage didn't fail like it should", element);

    }

    public void testDelegationWithoutVomsLimitClient() throws Exception {

        // Logger LOGGERRoot = Logger.getLogger("org.glite.security");
        // Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %l %x - %m%n");
        // Appender appender = new ConsoleAppender(lay);
        // LOGGERRoot.addAppender(appender);
        // LOGGERRoot.setLevel(Level.DEBUG);

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
        } catch (Exception e) {
            // ignore
        }

        String req = delegation.getProxyReq(delegationId, certChain);

        // client side new proxy signing
        GrDProxyDlgorOptions dopts = new GrDProxyDlgorOptions();
        dopts.setDlgorCertFile(proxyfile);
        dopts.setLimited(true);

        DelegationHandler handler = new DelegationHandler(req, delegationId, dopts);
        String certString = handler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, certString, certChain);

        // get the delegated credentials from the storage
        GrDPStorageFactory stgFactory = GrDPX509Util.getGrDPStorageFactory(opts.getDlgeeStorageFactory());
        GrDPStorage storage = stgFactory.createGrDPStorage(opts);
        CertInfoTriple info = new CertInfoTriple(certChain, null, false);

        GrDPStorageElement element = storage.findGrDPStorageElement(delegationId, info.dn);

        PEMCredential newCredential = new PEMCredential(new ByteArrayInputStream(element.getCertificate().getBytes()),
                (char[]) null);

        RSAKey pubKey = (RSAKey) newCredential.getCertificateChain()[0].getPublicKey();
        RSAPrivateCrtKey newKey = (RSAPrivateCrtKey) newCredential.getKey();

        BigInteger pubModulus = pubKey.getModulus();
        BigInteger privModulus = newKey.getModulus();
        assertEquals("Private key and public key of delegated credentials don't match.", pubModulus, privModulus);

        OpensslCertChainValidator validator = getValidator();
        ValidationResult result = validator.validate(newCredential.getCertificateChain());
        assertTrue(result.isValid());
        
        ProxyChainInfo newProxyInfo = new ProxyChainInfo(newCredential.getCertificateChain());
        assertTrue("New proxy is not limited even though it should be.", newProxyInfo.isLimited());
        assertTrue("New proxy is not legacy proxy even though it should be", newProxyInfo.getProxyType() == ProxyChainType.LEGACY);
        
        // check getting the expiration time
        Calendar expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Original delegation exp time" + expTime.getTime().getTime());
        Calendar compareDate = new GregorianCalendar();
        compareDate.add(Calendar.HOUR, 12);
        assertTrue("Delegated credential expires too late", expTime.before(compareDate));
        compareDate.add(Calendar.SECOND, -3);
        assertTrue("Delegated credential expires too early", expTime.after(compareDate));
        Thread.sleep(1000);

        // test proxy renewal
        String renewReq = delegation.renewProxyReq(delegationId, certChain);
        DelegationHandler renewHandler = new DelegationHandler(renewReq, delegationId, dopts);
        String renewCertString = renewHandler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, renewCertString, certChain);
        expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Renewed delegation exp time" + expTime.getTime().getTime());
        compareDate.add(Calendar.SECOND, 3);
        // System.out.println(compareDate.getTime().getTime());
        // System.out.println("comparison returns: " + expTime.compareTo(compareDate));
        assertTrue("Delegated credential expires too early, renewal failed", expTime.after(compareDate));

        // verify the cache is empty and putting the delegation in again fails
        boolean exception = false;
        try {
            delegation.putProxy(delegationId, renewCertString, certChain);
        } catch (Exception e) {
            exception = true;
        }
        assertTrue("Putting already handled proxy didn't fail like it should", exception);

        //
        // remove delegation in the end
        delegation.destroy(delegationId, certChain);

        // verify the delegation is gone
        element = storage.findGrDPStorageElement(delegationId, info.dn);
        assertNull("Finding deleted proxy form storage didn't fail like it should", element);

    }

    public void testDelegationWithoutVomsLimitServer() throws Exception {

        // Logger LOGGERRoot = Logger.getLogger("org.glite.security");
        // Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %l %x - %m%n");
        // Appender appender = new ConsoleAppender(lay);
        // LOGGERRoot.addAppender(appender);
        // LOGGERRoot.setLevel(Level.DEBUG);

        String proxyfile = "src/test/certs/trusted_client.proxy.grid_proxy";
        String delegationId = "testID";

        // server side request generation
        GrDProxyDlgeeOptions opts = new GrDProxyDlgeeOptions();
        opts.setDlgeeKeySize(2048);
        opts.setDlgeeStorage("target");
        opts.setDlgeeStorageFactory("org.glite.security.delegation.storage.GrDPStorageFilesystemFactory");
        // for testing purposes
        opts.setRequireVomsAttributes(false);
        opts.setLimited(true);

        GliteDelegation delegation = new GliteDelegation(opts);
        X509Credential credential = new PEMCredential(proxyfile, (char[]) null);

        X509Certificate[] certChain = credential.getCertificateChain();

        // first try to remove old delegation in case one exists.
        try {
            delegation.destroy(delegationId, certChain);
        } catch (Exception e) {
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

        // get the delegated credentials from the storage
        GrDPStorageFactory stgFactory = GrDPX509Util.getGrDPStorageFactory(opts.getDlgeeStorageFactory());
        GrDPStorage storage = stgFactory.createGrDPStorage(opts);
        CertInfoTriple info = new CertInfoTriple(certChain, null, false);

        GrDPStorageElement element = storage.findGrDPStorageElement(delegationId, info.dn);

        PEMCredential newCredential = new PEMCredential(new ByteArrayInputStream(element.getCertificate().getBytes()),
                (char[]) null);

        RSAKey pubKey = (RSAKey) newCredential.getCertificateChain()[0].getPublicKey();
        RSAPrivateCrtKey newKey = (RSAPrivateCrtKey) newCredential.getKey();

        BigInteger pubModulus = pubKey.getModulus();
        BigInteger privModulus = newKey.getModulus();
        assertEquals("Private key and public key of delegated credentials don't match.", pubModulus, privModulus);

        OpensslCertChainValidator validator = getValidator();
        ValidationResult result = validator.validate(newCredential.getCertificateChain());
        assertTrue(result.isValid());
        
        ProxyChainInfo newProxyInfo = new ProxyChainInfo(newCredential.getCertificateChain());
        assertTrue("New proxy is not limited even though it should be.", newProxyInfo.isLimited());
        assertTrue("New proxy is not legacy proxy even though it should be", newProxyInfo.getProxyType() == ProxyChainType.LEGACY);
        
        // check getting the expiration time
        Calendar expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Original delegation exp time" + expTime.getTime().getTime());
        Calendar compareDate = new GregorianCalendar();
        compareDate.add(Calendar.HOUR, 12);
        assertTrue("Delegated credential expires too late", expTime.before(compareDate));
        compareDate.add(Calendar.SECOND, -3);
        assertTrue("Delegated credential expires too early", expTime.after(compareDate));
        Thread.sleep(1000);

        // test proxy renewal
        String renewReq = delegation.renewProxyReq(delegationId, certChain);
        DelegationHandler renewHandler = new DelegationHandler(renewReq, delegationId, dopts);
        String renewCertString = renewHandler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, renewCertString, certChain);
        expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Renewed delegation exp time" + expTime.getTime().getTime());
        compareDate.add(Calendar.SECOND, 3);
        // System.out.println(compareDate.getTime().getTime());
        // System.out.println("comparison returns: " + expTime.compareTo(compareDate));
        assertTrue("Delegated credential expires too early, renewal failed", expTime.after(compareDate));

        // verify the cache is empty and putting the delegation in again fails
        boolean exception = false;
        try {
            delegation.putProxy(delegationId, renewCertString, certChain);
        } catch (Exception e) {
            exception = true;
        }
        assertTrue("Putting already handled proxy didn't fail like it should", exception);

        //
        // remove delegation in the end
        delegation.destroy(delegationId, certChain);

        // verify the delegation is gone
        element = storage.findGrDPStorageElement(delegationId, info.dn);
        assertNull("Finding deleted proxy form storage didn't fail like it should", element);

    }

    public void testDelegationWithoutVomsRfcProxy() throws Exception {

        // Logger LOGGERRoot = Logger.getLogger("org.glite.security");
        // Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %l %x - %m%n");
        // Appender appender = new ConsoleAppender(lay);
        // LOGGERRoot.addAppender(appender);
        // LOGGERRoot.setLevel(Level.DEBUG);

        String proxyfile = "src/test/certs/trusted_client.proxy_rfc.grid_proxy";
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
        } catch (Exception e) {
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

        // get the delegated credentials from the storage
        GrDPStorageFactory stgFactory = GrDPX509Util.getGrDPStorageFactory(opts.getDlgeeStorageFactory());
        GrDPStorage storage = stgFactory.createGrDPStorage(opts);
        CertInfoTriple info = new CertInfoTriple(certChain, null, false);

        GrDPStorageElement element = storage.findGrDPStorageElement(delegationId, info.dn);

        PEMCredential newCredential = new PEMCredential(new ByteArrayInputStream(element.getCertificate().getBytes()),
                (char[]) null);

        RSAKey pubKey = (RSAKey) newCredential.getCertificateChain()[0].getPublicKey();
        RSAPrivateCrtKey newKey = (RSAPrivateCrtKey) newCredential.getKey();

        BigInteger pubModulus = pubKey.getModulus();
        BigInteger privModulus = newKey.getModulus();
        assertEquals("Private key and public key of delegated credentials don't match.", pubModulus, privModulus);

        OpensslCertChainValidator validator = getValidator();
        ValidationResult result = validator.validate(newCredential.getCertificateChain());
        assertTrue(result.isValid());
        
        ProxyChainInfo newProxyInfo = new ProxyChainInfo(newCredential.getCertificateChain());
        assertFalse("New proxy is limited even though it should not be.", newProxyInfo.isLimited());
        assertTrue("New proxy is not RFC3820 proxy even though it should be", newProxyInfo.getProxyType() == ProxyChainType.RFC3820);

        // check getting the expiration time
        Calendar expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Original delegation exp time" + expTime.getTime().getTime());
        Calendar compareDate = new GregorianCalendar();
        compareDate.add(Calendar.HOUR, 12);
        assertTrue("Delegated credential expires too late", expTime.before(compareDate));
        compareDate.add(Calendar.SECOND, -3);
        assertTrue("Delegated credential expires too early", expTime.after(compareDate));
        Thread.sleep(1000);

        // test proxy renewal
        String renewReq = delegation.renewProxyReq(delegationId, certChain);
        DelegationHandler renewHandler = new DelegationHandler(renewReq, delegationId, dopts);
        String renewCertString = renewHandler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, renewCertString, certChain);
        expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Renewed delegation exp time" + expTime.getTime().getTime());
        compareDate.add(Calendar.SECOND, 3);
        // System.out.println(compareDate.getTime().getTime());
        // System.out.println("comparison returns: " + expTime.compareTo(compareDate));
        assertTrue("Delegated credential expires too early, renewal failed", expTime.after(compareDate));

        // verify the cache is empty and putting the delegation in again fails
        boolean exception = false;
        try {
            delegation.putProxy(delegationId, renewCertString, certChain);
        } catch (Exception e) {
            exception = true;
        }
        assertTrue("Putting already handled proxy didn't fail like it should", exception);

        //
        // remove delegation in the end
        delegation.destroy(delegationId, certChain);

        // verify the delegation is gone
        element = storage.findGrDPStorageElement(delegationId, info.dn);
        assertNull("Finding deleted proxy form storage didn't fail like it should", element);

    }

    public void testDelegationWithoutVomsRfcProxyLimitClient() throws Exception {

        // Logger LOGGERRoot = Logger.getLogger("org.glite.security");
        // Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %l %x - %m%n");
        // Appender appender = new ConsoleAppender(lay);
        // LOGGERRoot.addAppender(appender);
        // LOGGERRoot.setLevel(Level.DEBUG);

        String proxyfile = "src/test/certs/trusted_client.proxy_rfc.grid_proxy";
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
        } catch (Exception e) {
            // ignore
        }

        String req = delegation.getProxyReq(delegationId, certChain);

        // client side new proxy signing
        GrDProxyDlgorOptions dopts = new GrDProxyDlgorOptions();
        dopts.setDlgorCertFile(proxyfile);
        dopts.setLimited(true);

        DelegationHandler handler = new DelegationHandler(req, delegationId, dopts);
        String certString = handler.getPEMProxyCertificate();

        ProxyChainInfo generatedProxyInfo = new ProxyChainInfo(handler.getProxyCertificate());
        assertTrue("Generated proxy is not limited even though it should be.", generatedProxyInfo.isLimited());

        // server side new proxy storage
        delegation.putProxy(delegationId, certString, certChain);

        // get the delegated credentials from the storage
        GrDPStorageFactory stgFactory = GrDPX509Util.getGrDPStorageFactory(opts.getDlgeeStorageFactory());
        GrDPStorage storage = stgFactory.createGrDPStorage(opts);
        CertInfoTriple info = new CertInfoTriple(certChain, null, false);

        GrDPStorageElement element = storage.findGrDPStorageElement(delegationId, info.dn);

        PEMCredential newCredential = new PEMCredential(new ByteArrayInputStream(element.getCertificate().getBytes()),
                (char[]) null);

        RSAKey pubKey = (RSAKey) newCredential.getCertificateChain()[0].getPublicKey();
        RSAPrivateCrtKey newKey = (RSAPrivateCrtKey) newCredential.getKey();

        BigInteger pubModulus = pubKey.getModulus();
        BigInteger privModulus = newKey.getModulus();
        assertEquals("Private key and public key of delegated credentials don't match.", pubModulus, privModulus);

        OpensslCertChainValidator validator = getValidator();
        ValidationResult result = validator.validate(newCredential.getCertificateChain());
        assertTrue(result.isValid());
        
        ProxyChainInfo newProxyInfo = new ProxyChainInfo(newCredential.getCertificateChain());
//        assertTrue("New proxy is not limited even though it should be.", newProxyInfo.isLimited());
        assertTrue("New proxy is not RFC3820 proxy even though it should be", newProxyInfo.getProxyType() == ProxyChainType.RFC3820);

        // check getting the expiration time
        Calendar expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Original delegation exp time" + expTime.getTime().getTime());
        Calendar compareDate = new GregorianCalendar();
        compareDate.add(Calendar.HOUR, 12);
        assertTrue("Delegated credential expires too late", expTime.before(compareDate));
        compareDate.add(Calendar.SECOND, -3);
        assertTrue("Delegated credential expires too early", expTime.after(compareDate));
        Thread.sleep(1000);

        // test proxy renewal
        String renewReq = delegation.renewProxyReq(delegationId, certChain);
        DelegationHandler renewHandler = new DelegationHandler(renewReq, delegationId, dopts);
        String renewCertString = renewHandler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, renewCertString, certChain);
        expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Renewed delegation exp time" + expTime.getTime().getTime());
        compareDate.add(Calendar.SECOND, 3);
        // System.out.println(compareDate.getTime().getTime());
        // System.out.println("comparison returns: " + expTime.compareTo(compareDate));
        assertTrue("Delegated credential expires too early, renewal failed", expTime.after(compareDate));

        // verify the cache is empty and putting the delegation in again fails
        boolean exception = false;
        try {
            delegation.putProxy(delegationId, renewCertString, certChain);
        } catch (Exception e) {
            exception = true;
        }
        assertTrue("Putting already handled proxy didn't fail like it should", exception);

        //
        // remove delegation in the end
        delegation.destroy(delegationId, certChain);

        // verify the delegation is gone
        element = storage.findGrDPStorageElement(delegationId, info.dn);
        assertNull("Finding deleted proxy form storage didn't fail like it should", element);

    }

    public void testDelegationWithoutVomsRfcProxyLimitServer() throws Exception {

        // Logger LOGGERRoot = Logger.getLogger("org.glite.security");
        // Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %l %x - %m%n");
        // Appender appender = new ConsoleAppender(lay);
        // LOGGERRoot.addAppender(appender);
        // LOGGERRoot.setLevel(Level.DEBUG);

        String proxyfile = "src/test/certs/trusted_client.proxy_rfc.grid_proxy";
        String delegationId = "testID";

        // server side request generation
        GrDProxyDlgeeOptions opts = new GrDProxyDlgeeOptions();
        opts.setDlgeeKeySize(2048);
        opts.setDlgeeStorage("target");
        opts.setDlgeeStorageFactory("org.glite.security.delegation.storage.GrDPStorageFilesystemFactory");
        // for testing purposes
        opts.setRequireVomsAttributes(false);
        opts.setLimited(true);

        GliteDelegation delegation = new GliteDelegation(opts);
        X509Credential credential = new PEMCredential(proxyfile, (char[]) null);

        X509Certificate[] certChain = credential.getCertificateChain();

        // first try to remove old delegation in case one exists.
        try {
            delegation.destroy(delegationId, certChain);
        } catch (Exception e) {
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

        // get the delegated credentials from the storage
        GrDPStorageFactory stgFactory = GrDPX509Util.getGrDPStorageFactory(opts.getDlgeeStorageFactory());
        GrDPStorage storage = stgFactory.createGrDPStorage(opts);
        CertInfoTriple info = new CertInfoTriple(certChain, null, false);

        GrDPStorageElement element = storage.findGrDPStorageElement(delegationId, info.dn);

        PEMCredential newCredential = new PEMCredential(new ByteArrayInputStream(element.getCertificate().getBytes()),
                (char[]) null);

        RSAKey pubKey = (RSAKey) newCredential.getCertificateChain()[0].getPublicKey();
        RSAPrivateCrtKey newKey = (RSAPrivateCrtKey) newCredential.getKey();

        BigInteger pubModulus = pubKey.getModulus();
        BigInteger privModulus = newKey.getModulus();
        assertEquals("Private key and public key of delegated credentials don't match.", pubModulus, privModulus);

        OpensslCertChainValidator validator = getValidator();
        ValidationResult result = validator.validate(newCredential.getCertificateChain());
        assertTrue(result.isValid());
        
        ProxyChainInfo newProxyInfo = new ProxyChainInfo(newCredential.getCertificateChain());
//        assertTrue("New proxy is not limited even though it should be.", newProxyInfo.isLimited());
        assertTrue("New proxy is not RFC3820 proxy even though it should be", newProxyInfo.getProxyType() == ProxyChainType.RFC3820);

        // check getting the expiration time
        Calendar expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Original delegation exp time" + expTime.getTime().getTime());
        Calendar compareDate = new GregorianCalendar();
        compareDate.add(Calendar.HOUR, 12);
        assertTrue("Delegated credential expires too late", expTime.before(compareDate));
        compareDate.add(Calendar.SECOND, -3);
        assertTrue("Delegated credential expires too early", expTime.after(compareDate));
        Thread.sleep(1000);

        // test proxy renewal
        String renewReq = delegation.renewProxyReq(delegationId, certChain);
        DelegationHandler renewHandler = new DelegationHandler(renewReq, delegationId, dopts);
        String renewCertString = renewHandler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, renewCertString, certChain);
        expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Renewed delegation exp time" + expTime.getTime().getTime());
        compareDate.add(Calendar.SECOND, 3);
        // System.out.println(compareDate.getTime().getTime());
        // System.out.println("comparison returns: " + expTime.compareTo(compareDate));
        assertTrue("Delegated credential expires too early, renewal failed", expTime.after(compareDate));

        // verify the cache is empty and putting the delegation in again fails
        boolean exception = false;
        try {
            delegation.putProxy(delegationId, renewCertString, certChain);
        } catch (Exception e) {
            exception = true;
        }
        assertTrue("Putting already handled proxy didn't fail like it should", exception);

        //
        // remove delegation in the end
        delegation.destroy(delegationId, certChain);

        // verify the delegation is gone
        element = storage.findGrDPStorageElement(delegationId, info.dn);
        assertNull("Finding deleted proxy form storage didn't fail like it should", element);

    }

    public void testDelegationWithoutVomsWithGetNew() throws Exception {

        // Logger LOGGERRoot = Logger.getLogger("org.glite.security");
        // Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %l %x - %m%n");
        // Appender appender = new ConsoleAppender(lay);
        // LOGGERRoot.addAppender(appender);
        // LOGGERRoot.setLevel(Level.DEBUG);

        String proxyfile = "src/test/certs/trusted_client.proxy.grid_proxy";
        String delegationId = null;

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
        } catch (Exception e) {
            // ignore
        }

        NewProxyReq reqObj = delegation.getNewProxyReq(delegationId, certChain);

        // client side new proxy signing
        GrDProxyDlgorOptions dopts = new GrDProxyDlgorOptions();
        dopts.setDlgorCertFile(proxyfile);

        DelegationHandler handler = new DelegationHandler(reqObj.getProxyRequest(), delegationId, dopts);
        String certString = handler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, certString, certChain);

        // get the delegated credentials from the storage
        GrDPStorageFactory stgFactory = GrDPX509Util.getGrDPStorageFactory(opts.getDlgeeStorageFactory());
        GrDPStorage storage = stgFactory.createGrDPStorage(opts);
        CertInfoTriple info = new CertInfoTriple(certChain, null, false);

        GrDPStorageElement element = storage.findGrDPStorageElement(reqObj.getDelegationID(), info.dn);

        PEMCredential newCredential = new PEMCredential(new ByteArrayInputStream(element.getCertificate().getBytes()),
                (char[]) null);

        RSAKey pubKey = (RSAKey) newCredential.getCertificateChain()[0].getPublicKey();
        RSAPrivateCrtKey newKey = (RSAPrivateCrtKey) newCredential.getKey();

        BigInteger pubModulus = pubKey.getModulus();
        BigInteger privModulus = newKey.getModulus();
        assertEquals("Private key and public key of delegated credentials don't match.", pubModulus, privModulus);

        // check getting the expiration time
        Calendar expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Original delegation exp time" + expTime.getTime().getTime());
        Calendar compareDate = new GregorianCalendar();
        compareDate.add(Calendar.HOUR, 12);
        assertTrue("Delegated credential expires too late", expTime.before(compareDate));
        compareDate.add(Calendar.SECOND, -3);
        assertTrue("Delegated credential expires too early", expTime.after(compareDate));
        Thread.sleep(1000);

        // test proxy renewal
        String renewReq = delegation.renewProxyReq(delegationId, certChain);
        DelegationHandler renewHandler = new DelegationHandler(renewReq, delegationId, dopts);
        String renewCertString = renewHandler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, renewCertString, certChain);
        expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Renewed delegation exp time" + expTime.getTime().getTime());
        compareDate.add(Calendar.SECOND, 3);
        // System.out.println(compareDate.getTime().getTime());
        // System.out.println("comparison returns: " + expTime.compareTo(compareDate));
        assertTrue("Delegated credential expires too early, renewal failed", expTime.after(compareDate));

        // verify the cache is empty and putting the delegation in again fails
        boolean exception = false;
        try {
            delegation.putProxy(delegationId, renewCertString, certChain);
        } catch (Exception e) {
            exception = true;
        }
        assertTrue("Putting already handled proxy didn't fail like it should", exception);

        //
        // remove delegation in the end
        delegation.destroy(delegationId, certChain);

        // verify the delegation is gone
        element = storage.findGrDPStorageElement(delegationId, info.dn);
        assertNull("Finding deleted proxy form storage didn't fail like it should", element);

    }

    public void testDelegationWithoutVomsWithGetNewUseID() throws Exception {

        // Logger LOGGERRoot = Logger.getLogger("org.glite.security");
        // Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %l %x - %m%n");
        // Appender appender = new ConsoleAppender(lay);
        // LOGGERRoot.addAppender(appender);
        // LOGGERRoot.setLevel(Level.DEBUG);

        String proxyfile = "src/test/certs/trusted_client.proxy.grid_proxy";
        String delegationId = null;

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
        } catch (Exception e) {
            // ignore
        }

        NewProxyReq reqObj = delegation.getNewProxyReq(delegationId, certChain);

        // client side new proxy signing
        GrDProxyDlgorOptions dopts = new GrDProxyDlgorOptions();
        dopts.setDlgorCertFile(proxyfile);
        delegationId = reqObj.getDelegationID();

        DelegationHandler handler = new DelegationHandler(reqObj.getProxyRequest(), delegationId, dopts);
        String certString = handler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, certString, certChain);

        // get the delegated credentials from the storage
        GrDPStorageFactory stgFactory = GrDPX509Util.getGrDPStorageFactory(opts.getDlgeeStorageFactory());
        GrDPStorage storage = stgFactory.createGrDPStorage(opts);
        CertInfoTriple info = new CertInfoTriple(certChain, null, false);

        GrDPStorageElement element = storage.findGrDPStorageElement(reqObj.getDelegationID(), info.dn);

        PEMCredential newCredential = new PEMCredential(new ByteArrayInputStream(element.getCertificate().getBytes()),
                (char[]) null);

        RSAKey pubKey = (RSAKey) newCredential.getCertificateChain()[0].getPublicKey();
        RSAPrivateCrtKey newKey = (RSAPrivateCrtKey) newCredential.getKey();

        BigInteger pubModulus = pubKey.getModulus();
        BigInteger privModulus = newKey.getModulus();
        assertEquals("Private key and public key of delegated credentials don't match.", pubModulus, privModulus);

        // check getting the expiration time
        Calendar expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Original delegation exp time" + expTime.getTime().getTime());
        Calendar compareDate = new GregorianCalendar();
        compareDate.add(Calendar.HOUR, 12);
        assertTrue("Delegated credential expires too late", expTime.before(compareDate));
        compareDate.add(Calendar.SECOND, -3);
        assertTrue("Delegated credential expires too early", expTime.after(compareDate));
        Thread.sleep(1000);

        // test proxy renewal
        String renewReq = delegation.renewProxyReq(delegationId, certChain);
        DelegationHandler renewHandler = new DelegationHandler(renewReq, delegationId, dopts);
        String renewCertString = renewHandler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, renewCertString, certChain);
        expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Renewed delegation exp time" + expTime.getTime().getTime());
        compareDate.add(Calendar.SECOND, 3);
        // System.out.println(compareDate.getTime().getTime());
        // System.out.println("comparison returns: " + expTime.compareTo(compareDate));
        assertTrue("Delegated credential expires too early, renewal failed", expTime.after(compareDate));

        // verify the cache is empty and putting the delegation in again fails
        boolean exception = false;
        try {
            delegation.putProxy(delegationId, renewCertString, certChain);
        } catch (Exception e) {
            exception = true;
        }
        assertTrue("Putting already handled proxy didn't fail like it should", exception);

        //
        // remove delegation in the end
        delegation.destroy(delegationId, certChain);

        // verify the delegation is gone
        element = storage.findGrDPStorageElement(delegationId, info.dn);
        assertNull("Finding deleted proxy form storage didn't fail like it should", element);

    }

    public void testDelegationWithVoms() throws Exception {

        // Logger LOGGERRoot = Logger.getLogger("org");
        // Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %l %x - %m%n");
        // Appender appender = new ConsoleAppender(lay);
        // LOGGERRoot.addAppender(appender);
        // LOGGERRoot.setLevel(Level.DEBUG);

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
        } catch (Exception e) {
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

        // get the delegated credentials from the storage
        GrDPStorageFactory stgFactory = GrDPX509Util.getGrDPStorageFactory(opts.getDlgeeStorageFactory());
        GrDPStorage storage = stgFactory.createGrDPStorage(opts);
        CertInfoTriple info = new CertInfoTriple(certChain, null, false);

        GrDPStorageElement element = storage.findGrDPStorageElement(delegationId, info.dn);

        PEMCredential newCredential = new PEMCredential(new ByteArrayInputStream(element.getCertificate().getBytes()),
                (char[]) null);

        RSAKey pubKey = (RSAKey) newCredential.getCertificateChain()[0].getPublicKey();
        RSAPrivateCrtKey newKey = (RSAPrivateCrtKey) newCredential.getKey();

        BigInteger pubModulus = pubKey.getModulus();
        BigInteger privModulus = newKey.getModulus();
        assertEquals("Private key and public key of delegated credentials don't match.", pubModulus, privModulus);

        // check getting the expiration time
        Calendar expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Original delegation exp time" + expTime.getTime().getTime());
        Calendar compareDate = new GregorianCalendar();
        compareDate.add(Calendar.HOUR, 12);
        assertTrue("Delegated credential expires too late", expTime.before(compareDate));
        compareDate.add(Calendar.SECOND, -3);
        assertTrue("Delegated credential expires too early", expTime.after(compareDate));
        Thread.sleep(1000);

        // test proxy renewal
        String renewReq = delegation.renewProxyReq(delegationId, certChain);
        DelegationHandler renewHandler = new DelegationHandler(renewReq, delegationId, dopts);
        String renewCertString = renewHandler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, renewCertString, certChain);
        expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Renewed delegation exp time" + expTime.getTime().getTime());
        compareDate.add(Calendar.SECOND, 3);
        // System.out.println(compareDate.getTime().getTime());
        // System.out.println("comparison returns: " + expTime.compareTo(compareDate));
        assertTrue("Delegated credential expires too early, renewal failed", expTime.after(compareDate));

        // verify the cache is empty and putting the delegation in again fails
        boolean exception = false;
        try {
            delegation.putProxy(delegationId, renewCertString, certChain);
        } catch (Exception e) {
            exception = true;
        }
        assertTrue("Putting already handled proxy didn't fail like it should", exception);

        // remove delegation in the end
        delegation.destroy(delegationId, certChain);

        // verify the delegation is gone
        element = storage.findGrDPStorageElement(delegationId, info.dn);
        assertNull("Finding deleted proxy form storage didn't fail like it should", element);

    }

    public void testDelegationWithVomsNoID() throws Exception {

        // Logger LOGGERRoot = Logger.getLogger("org");
        // Layout lay = new PatternLayout("%d{ISO8601} %-5p [%t] %l %x - %m%n");
        // Appender appender = new ConsoleAppender(lay);
        // LOGGERRoot.addAppender(appender);
        // LOGGERRoot.setLevel(Level.DEBUG);

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
        } catch (Exception e) {
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

        // get the delegated credentials from the storage
        GrDPStorageFactory stgFactory = GrDPX509Util.getGrDPStorageFactory(opts.getDlgeeStorageFactory());
        GrDPStorage storage = stgFactory.createGrDPStorage(opts);
        CertInfoTriple info = new CertInfoTriple(certChain, null, false);
        String tempDelId = GrDPX509Util.genDlgID(info.dn, new String[] { "/utoVO", "/utoVO/testgr" });

        GrDPStorageElement element = storage.findGrDPStorageElement(tempDelId, info.dn);

        PEMCredential newCredential = new PEMCredential(new ByteArrayInputStream(element.getCertificate().getBytes()),
                (char[]) null);

        RSAKey pubKey = (RSAKey) newCredential.getCertificateChain()[0].getPublicKey();
        RSAPrivateCrtKey newKey = (RSAPrivateCrtKey) newCredential.getKey();

        BigInteger pubModulus = pubKey.getModulus();
        BigInteger privModulus = newKey.getModulus();
        assertEquals("Private key and public key of delegated credentials don't match.", pubModulus, privModulus);

        // check getting the expiration time
        Calendar expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Original delegation exp time" + expTime.getTime().getTime());
        Calendar compareDate = new GregorianCalendar();
        compareDate.add(Calendar.HOUR, 12);
        assertTrue("Delegated credential expires too late", expTime.before(compareDate));
        compareDate.add(Calendar.SECOND, -3);
        assertTrue("Delegated credential expires too early", expTime.after(compareDate));
        Thread.sleep(1000);

        // test proxy renewal
        String renewReq = delegation.renewProxyReq(delegationId, certChain);
        DelegationHandler renewHandler = new DelegationHandler(renewReq, delegationId, dopts);
        String renewCertString = renewHandler.getPEMProxyCertificate();

        // server side new proxy storage
        delegation.putProxy(delegationId, renewCertString, certChain);
        expTime = delegation.getTerminationTime(delegationId, certChain);
        // System.out.println("Renewed delegation exp time" + expTime.getTime().getTime());
        compareDate.add(Calendar.SECOND, 3);
        // System.out.println(compareDate.getTime().getTime());
        // System.out.println("comparison returns: " + expTime.compareTo(compareDate));
        assertTrue("Delegated credential expires too early, renewal failed", expTime.after(compareDate));

        // verify the cache is empty and putting the delegation in again fails
        boolean exception = false;
        try {
            delegation.putProxy(delegationId, renewCertString, certChain);
        } catch (Exception e) {
            exception = true;
        }
        assertTrue("Putting already handled proxy didn't fail like it should", exception);

        // remove delegation in the end
        delegation.destroy(delegationId, certChain);

        // verify the delegation is gone
        element = storage.findGrDPStorageElement(tempDelId, info.dn);
        assertNull("Finding deleted proxy form storage didn't fail like it should", element);

    }

}
