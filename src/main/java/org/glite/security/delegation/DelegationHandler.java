/*
 * Copyright (c) Members of the EGEE Collaboration. 2004. See
 * http://www.eu-egee.org/partners/ for details on the copyright holders.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.glite.security.delegation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMReader;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.impl.PEMCredential;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.emi.security.authn.x509.proxy.ProxyCSRInfo;
import eu.emi.security.authn.x509.proxy.ProxyChainInfo;
import eu.emi.security.authn.x509.proxy.ProxyGenerator;
import eu.emi.security.authn.x509.proxy.ProxyPolicy;
import eu.emi.security.authn.x509.proxy.ProxyRequestOptions;
import eu.emi.security.authn.x509.proxy.ProxyType;

/**
 * The delegation handler class for the client side
 */
public class DelegationHandler {
    private static final Logger LOGGER = Logger.getLogger(DelegationHandler.class);
    private X509Certificate[] m_certs = null;
    private String strX509CertChain = null;

    /**
     * Class constructor
     * 
     * @param certReq Service certificate request
     * @param delegationID Delegation identifier
     * @param propFile location of properties file
     */
    public DelegationHandler(String certReq, String delegationID, String propFile) throws Exception {
        GrDProxyDlgorOptions dlgorOpt = null;
        try {
            dlgorOpt = new GrDProxyDlgorOptions(propFile);
        } catch (IOException e2) {
            LOGGER.error("failed to read delegation options from: " + propFile
                    + " nor from default location. Error was: " + e2.getMessage());
            return;
        }

        requestHandler(certReq, delegationID, dlgorOpt);
    }

    /**
     * Class constructor
     * 
     * @param certReq Service certificate request.
     * @param delegationID Delegation identifier.
     * @param opts the delegation options, given as a GrDProxyDlgorOptions class.
     */
    public DelegationHandler(String certReq, String delegationID, GrDProxyDlgorOptions opts) throws Exception {
        requestHandler(certReq, delegationID, opts);
    }

    /**
     * Handles the service certificate request and generates a proxy certificate. Stores the new proxy certificate in
     * proxyStorage
     * 
     * @param certReq Certificate request received form the server.
     * @param delegationID Delegation identifier
     * @param propFile location of properties file
     * @return Generated proxy certificate
     */
    private void requestHandler(String certReq, String delegationID, GrDProxyDlgorOptions dlgorOpt) throws Exception {
        try {
            LOGGER.debug("User Cert/Proxy File" + dlgorOpt.getDlgorCertFile());
            LOGGER.debug("User Key/Proxy File" + dlgorOpt.getDlgorKeyFile());
            LOGGER.debug("User Password" + dlgorOpt.getDlgorPass());
            LOGGER.debug("Certificate Request" + certReq);

            char[] pass = null;
            if (dlgorOpt.getDlgorPass() != null) {
                pass = dlgorOpt.getDlgorPass().toCharArray();
            }

            PEMCredential pemCredential = null;
            // if no keyfile given, assume it's a proxy.
            if (dlgorOpt.getDlgorKeyFile() == null) {
                pemCredential = new PEMCredential(dlgorOpt.getDlgorCertFile(), pass);
            } else {
                pemCredential = new PEMCredential(dlgorOpt.getDlgorCertFile(), dlgorOpt.getDlgorKeyFile(), pass);
            }

            X509Certificate[] certs = pemCredential.getCertificateChain();

            for (int n = 0; n < certs.length; n++) {
                LOGGER.debug("cert [" + n + "] is from "
                        + X500NameUtils.getReadableForm(certs[n].getSubjectX500Principal()));
            }

            PEMReader pemReader = new PEMReader(new StringReader(certReq));
            PKCS10CertificationRequest req;
            try {
                req = (PKCS10CertificationRequest) pemReader.readObject();
            } catch (IOException e1) {
                LOGGER.error("Could not load the original certificate request from cache.");
                throw new DelegationException("Could not load the original certificate request from cache: "
                        + e1.getMessage());
            } finally {
                pemReader.close();
            }

            ProxyRequestOptions options = new ProxyRequestOptions(certs, req);
            
            ProxyCSRInfo reqInfo = new ProxyCSRInfo(req);
            
            options.setType(reqInfo.getProxyType());
            
            ProxyChainInfo info = new ProxyChainInfo(certs);
            
            boolean reqLimited = false;
            if(reqInfo.isLimited() != null){
                reqLimited = reqInfo.isLimited().booleanValue();
            }

            if(dlgorOpt.isLimited() || reqLimited || info.isLimited()){
                if(reqInfo.getProxyType() != ProxyType.LEGACY){
                    options.setPolicy(new ProxyPolicy(ProxyPolicy.LIMITED_PROXY_OID));
                }
                options.setLimited(true);
            }
            
            if(dlgorOpt.getTracingIssuer() != null){
                options.setProxyTracingIssuer(dlgorOpt.getTracingIssuer());
            }
            
            if(dlgorOpt.getTracingSubject() != null){
                options.setProxyTracingSubject(dlgorOpt.getTracingSubject());
            }
            
            m_certs = ProxyGenerator.generate(options, pemCredential.getKey());

            ByteArrayOutputStream stream = new ByteArrayOutputStream();

            CertificateUtils.saveCertificateChain(stream, m_certs, Encoding.PEM);

            strX509CertChain = stream.toString();
        } catch (Exception e) {
            LOGGER.error("Proxy generation failed: " + e);
            throw e;
        }
    }

    /**
     * Return generated proxy certificate
     * 
     * @return Generated proxy certificate
     */
    public X509Certificate[] getProxyCertificate() throws Exception {
        return m_certs;
    }

    /**
     * Return generated proxy certificate in PEM format
     * 
     * @return Generated proxy certificate
     */
    public String getPEMProxyCertificate() {
        return strX509CertChain;
    }
}
