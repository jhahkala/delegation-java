package org.glite.security.delegation;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.italiangrid.voms.VOMSAttribute;
import org.italiangrid.voms.ac.VOMSACValidator;
import org.italiangrid.voms.ac.VOMSValidationResult;
import org.italiangrid.voms.error.VOMSValidationErrorMessage;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.emi.security.authn.x509.proxy.ProxyUtils;

/**
 * Simple class that processes the certificate chain and digs up the information
 * needed.
 * 
 * @author hahkala
 * 
 */
public class CertInfoTriple {
	/** the logging facility **/
	private static final Logger LOGGER = Logger.getLogger(CertInfoTriple.class);
	/** The end entity certificate from the certificate chain. */
	public X509Certificate endEntityCert = null;
	/** The end entity DN. */
	public String dn = null;
	/** The voms attributes from the proxy. */
	public String vomsAttributes[] = null;

	/**
	 * Digs up the information from the certificate chain.
	 * 
	 * @param certs
	 *            The certificate chain to process.
	 * @param requireVomsAttrs
	 *            Whether the voms attributes are required or not. If they are
	 *            required, and none are found, the DelegationException is
	 *            thrown. Also if they are required and an empty attribute is
	 *            found, the DelegationException is thrown.
	 * @throws DelegationException
	 *             Thrown in case no certificates are given, no end entity
	 *             certificate is found, no end entity DN is found or voms
	 *             attributes are required, but not found or invalid.
	 */
	public CertInfoTriple(X509Certificate certs[], VOMSACValidator validator, boolean requireVomsAttrs)
			throws DelegationException {
		if (certs == null) {
			throw new DelegationException("No certificates given.");
		}
		endEntityCert = ProxyUtils.getEndUserCertificate(certs);
		// System.out.println(endEntityCert);

		if (endEntityCert == null) {
			throw new DelegationException("No end entity certificate found on the certificate chain.");
		}

		// Get client DN
		dn = X500NameUtils.getReadableForm(endEntityCert.getSubjectX500Principal());
		// System.out.println(clientDN);
		if (dn == null) {
			throw new DelegationException("Failed to get client DN.");
		}

		if (validator != null) {
			try {
				vomsAttributes = getVomsAttributes(certs, validator);
			} catch (Exception e) {
				if (requireVomsAttrs) {
					throw new DelegationException("Failed to get required VOMS attributes " + e.getClass() + " "
							+ e.getMessage(), e);
				} else {
					LOGGER.warn(
							"VOMS attribute retrieval failed, but they are not required, so continuing. Error was: "
									+ e.getClass() + " " + e.getMessage(), e);
				}
			}
		}

		if (requireVomsAttrs) {
			if (vomsAttributes == null || vomsAttributes.length == 0) {
				throw new DelegationException("Failed to get required VOMS attributes.");
			}
			for (String attribute : vomsAttributes) {
				if (attribute == null || attribute.length() == 0) {
					throw new DelegationException("Invalid empty VOMS attribute found.");
				}
			}

		}
	}

	/**
	 * Uses the given voms validator to validate and extract the voms attributes
	 * from the certificate chain.
	 * 
	 * @param certs
	 *            the chain to treat.
	 * @return The validates attributes.
	 * @throws DelegationException
	 *             Thrown in case the voms AC validation fails.
	 */
	public String[] getVomsAttributes(X509Certificate certs[], VOMSACValidator validator) throws DelegationException {

		List<VOMSValidationResult> results = validator.validateWithResult(certs);

		ArrayList<String> attributeList = new ArrayList<String>();

		for (VOMSValidationResult r : results) {

			if (r.isValid()) {
				VOMSAttribute attrs = r.getAttributes();
				for (String attribute : attrs.getFQANs()) {
					attributeList.add(attribute);
				}
			} else {
				String error = "";
				for (VOMSValidationErrorMessage errorMessage : r.getValidationErrors()) {
					error = error + ", " + errorMessage;
				}
				throw new DelegationException("Error(s) while getting VOMS attributes: " + error);
			}
		}

		return attributeList.toArray(new String[attributeList.size()]);

	}

}
