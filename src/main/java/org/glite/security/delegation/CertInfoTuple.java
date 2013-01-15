package org.glite.security.delegation;

import java.security.cert.X509Certificate;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.emi.security.authn.x509.proxy.ProxyUtils;

/**
 * Simple class that processes the certificate chain and digs up the information
 * needed.
 * 
 * @author hahkala
 * 
 */
public class CertInfoTuple {
    /** The end entity certificate from the certificate chain. */
    public X509Certificate endEntityCert = null;
    /** The end entity DN. */
    public String dn = null;
    /** The voms attributes from the proxy. */
    public String vomsAttributes[] = null;

    /**
     * Digs up the information from the certificate chain.
     * 
     * @param certs The certificate chain to process.
     * @param requireVomsAttrs Whether the voms attributes are required or not.
     *            If they are required, and none are found, the
     *            DelegationException is thrown. Also if they are required and
     *            an empty attribute is found, the DelegationException is
     *            thrown.
     * @throws DelegationException Thrown in case no certificates are given, no
     *             end entity certificate is found, no end entity DN is found or
     *             voms attributes are required, but not found or invalid.
     */
    public CertInfoTuple(X509Certificate certs[], boolean requireVomsAttrs) throws DelegationException {
        if (certs == null) {
            throw new DelegationException("No certificates given.");
        }
        endEntityCert = ProxyUtils.getEndUserCertificate(certs);
//        System.out.println(endEntityCert);

        if (endEntityCert == null) {
            throw new DelegationException("No end entity certificate found on the certificate chain.");
        }

        // Get client DN
        dn = X500NameUtils.getReadableForm(endEntityCert.getSubjectX500Principal());
//        System.out.println(clientDN);
        if (dn == null) {
            throw new DelegationException("Failed to get client DN.");
        }

        vomsAttributes = GrDPX509Util.getVOMSAttributes(certs);

        if (requireVomsAttrs) {
            if (vomsAttributes == null || vomsAttributes.length == 0) {
                throw new DelegationException("Failed to get required voms attributes.");
            }
            for (String attribute : vomsAttributes) {
                if (attribute == null || attribute.length() == 0) {
                    throw new DelegationException("Invalid empty voms attribute found.");
                }
            }

        }
    }
}
