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

import java.io.IOException;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.JDKKeyPairGenerator;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.encoders.Hex;
import org.glite.security.delegation.storage.GrDPStorageFactory;
import org.italiangrid.voms.VOMSAttribute;
import org.italiangrid.voms.VOMSValidators;
import org.italiangrid.voms.ac.VOMSACValidator;

/**
 * Utility to manage X509 certificates
 * 
 * @author Mehran Ahsant
 * @author Akos Frohner <Akos.Frohner@cern.ch>
 * @author Joni Hahkala
 */
public class GrDPX509Util {
    private final static Logger LOGGER = Logger.getLogger(GrDPX509Util.class);
    public static final String CERT_CHAIN_CONTENT_TYPE = "application/x-x509-user-cert-chain";
    public static final String CERT_REQ_CONTENT_TYPE = "application/x-x509-cert-request";
    private static MessageDigest s_digester = null;
    private static VOMSACValidator vomsValidator = null;
    public static boolean windows = System.getProperty("os.name").startsWith("Windows");

    static {
        try {
            s_digester = MessageDigest.getInstance("SHA-1");
        } catch (Exception e) {
            LOGGER.fatal("Message digester implementation not found: " + e.getMessage(), e);
            throw new RuntimeException("Delegation utilities code initialization failed: " + e.getMessage(), e);
        }
        
    }

    /**
     * A synchronizer wrapper for the static digester, only access it through
     * this utility method.
     * 
     * @param input The bytes to digest.
     * @return the digested bytes.
     */
    public static synchronized byte[] digest(byte[] input) {
        // GrDPX509Util utils = new GrDPX509Util();
        return s_digester.digest(input);
    }

    /**
     * Change the access mode of a file in the filesystem (!!! system specific
     * !!!). I windows this method just returns with true.
     * 
     * @param file Location of the file to be changed.
     * @param mode New mode for the file.
     * @return True if file mode has changed.
     */
    public static boolean changeFileMode(String file, int mode) {
    	// in windows we can't change the mode, so skip
    	if(windows){
    		return true;
    	}
        Runtime runtime = Runtime.getRuntime();
        String[] cmd = new String[] { "chmod", String.valueOf(mode), file };

        try {
            Process process = runtime.exec(cmd, null);

            return (process.waitFor() == 0) ? true : false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Retrieves the location of the user cert file. from X509_USER_CERT.
     * 
     * @return String the location of the user cert file
     */
    public static String getDefaultCertFile() {
        String location = null;
        location = System.getProperty("X509_USER_CERT");

        return location;
    }

    /**
     * Retrieves the location of the user key file. from X509_USER_KEY.
     * 
     * @return String the location of the user key file
     */
    public static String getDefaultKeyFile() {
        String location = null;
        location = System.getProperty("X509_USER_KEY");

        return location;
    }

    /**
     * Retrieves the location of the CA cert files. from X509_CERT_DIR.
     * 
     * @return String the locations of the CA certificates
     */
    public static String getDefaultCertLocation() {
        String location = null;
        location = System.getProperty("X509_CERT_DIR");

        return location;
    }

    /**
     * Retrieves the location of the proxy file. from X509_USER_PROXY.
     * 
     * @return String the location of the proxy file
     */
    public static String getDefaultProxyFile() {
        String location;
        location = System.getProperty("X509_USER_PROXY");

        return location;
    }

    /**
     * Returns SHA1 hash digest of file name based on given delegationID and DER
     * encoded DN in form of SHA1_HASH(DelegationID)+"-"+SHA1_HASH(DN)
     * 
     * @param delegationid_in delegationID of proxy certificate
     * @param DN_in DER encoded DN
     * @return Digested file name
     */
    public static String digestFileName(String delegationid_in, String DN_in) {
        byte[] dgstDlgID = null;
        byte[] dgstDN = null;
        String filenameP1 = null;
        String filenameP2 = "-";
        String filenameP3 = null;

        dgstDlgID = digest(delegationid_in.getBytes());
        dgstDlgID = get8MostSignificant(dgstDlgID);
        filenameP1 = new String(Hex.encode(dgstDlgID));

        LOGGER.debug("DN TO DIGEST : " + DN_in.replaceAll(GrDPConstants.CNPROXY + ",", ""));

        dgstDN = digest((DN_in.replaceAll(GrDPConstants.CNPROXY + ",", "")).getBytes());

        dgstDN = get8MostSignificant(dgstDN);
        filenameP3 = new String(Hex.encode(dgstDN));

        // result = filename.digest( randomNum.getBytes() );

        LOGGER.debug("Digest of file name : " + filenameP1 + filenameP2 + filenameP3);

        return filenameP1 + filenameP2 + filenameP3;
    }

    /**
     * Returns 8 most significant bytes of byte array
     * 
     * @param input input byte array
     * @return 8 MS bytes
     */
    private static byte[] get8MostSignificant(byte[] input) {
        byte[] result = new byte[8];

        for (int i = 0; i <= 7; ++i)
            result[i] = input[i];

        return result;
    }

    /**
     * Returns 'n' most significant bytes of byte array
     * 
     * @param input input byte array
     * @return 'n' MS bytes
     */
    private static byte[] getMostSignificant(byte[] input, int n) {
        byte[] result = new byte[n];

        for (int i = 0; i <= n - 1; ++i)
            result[i] = input[i];

        return result;
    }

    /**
     * Returns a certificate request in HTTP MIME type format
     * 
     * @param certReq certificate request to response
     * @return http response format
     */
    public static String certReqResponse(String certReq) {
        // Constructing HTTP message headers.
        StringBuffer buffer = new StringBuffer();

        buffer.append("HTTP/1.1 200 ok\r\n");
        buffer.append("Content-type: " + CERT_REQ_CONTENT_TYPE + "\r\n\r\n");
        buffer.append(certReq);

        return buffer.toString();
    }

    /**
     * Returns a proxy certificate in HTTP MIME type format
     * 
     * @param proxyCert proxy certificate to response
     * @return http response format
     */
    public static String certProxyResponse(String proxyCert) {
        // Constructing HTTP message headers.
        StringBuffer buffer = new StringBuffer();

        buffer.append("HTTP/1.1 200 ok\r\n");
        buffer.append("Content-type: " + CERT_CHAIN_CONTENT_TYPE + "\r\n\r\n");
        buffer.append(proxyCert);

        return buffer.toString();
    }

    /**
     * Makes an HTTP error message out of the error message.
     * 
     * @param errorMsg to send
     * @return The HTTP error message.
     */
    public static String errorResponse(String errorMsg) {
        // Constructing HTTP message headers.
        StringBuffer buffer = new StringBuffer();

        buffer.append("HTTP/1.1 " + errorMsg + "\r\n");
        buffer.append("\r\n");

        return buffer.toString();
    }

    /**
     * Retrieve the path to the delegatee property file
     * 
     * @return Path to the porperty file
     */
    public static String getDlgeePropertyFile() {
        String dlgeePropertyFile = null;
        dlgeePropertyFile = System.getProperty("GLITE_DLGEE_PROPERTY", "dlgee.properties");

        LOGGER.debug("GLITE_DLGEE_PROPERTY : " + dlgeePropertyFile);

        return dlgeePropertyFile;
    }

    /**
     * Retrieve the path to the delegator property file
     * 
     * @return Path to the porperty file
     */
    public static String getDlgorPropertyFile() {
        String dlgorPropertyFile = null;
        dlgorPropertyFile = System.getProperty("GLITE_DLGOR_PROPERTY", "dlgor.properties");

        return dlgorPropertyFile;
    }

    /**
     * Get the factory to create storage instances.
     * 
     * @param factoryClass The full name of the class implementing the storage
     *            factory.
     * @return A factory for creating storage object instances.
     * @throws ClassNotFoundException Could not find the specified class in
     *             classpath
     * @throws NoSuchMethodException Failed to instantiate a factory object
     * @throws InvocationTargetException Failed to instantiate a factory object
     * @throws IllegalAccessException Failed to instantiate a factory object
     * @throws InstantiationException Failed to instantiate a factory object
     */
    public static GrDPStorageFactory getGrDPStorageFactory(String factoryClass) throws ClassNotFoundException,
            NoSuchMethodException, InvocationTargetException, IllegalAccessException, InstantiationException {
        LOGGER.debug("Entered getGrDStorage.");

        // Get the class references for the helper and DBManager objects
        Class<?> storageClass = Class.forName(factoryClass);
        LOGGER.debug("Successfully loaded class '" + factoryClass + "'");

        // Create a new helper object instance and return
        return (GrDPStorageFactory) storageClass.newInstance();
    }

    /**
     * Create a new certificate request.
     * 
     * @param subjectDN The dn to include in the certificate request.
     * @param sigAlgName The algorithm to be used.
     * @param keyPair The keypair to include in the certificate.
     * @return A PEM encoded certificate request.
     * @throws GeneralSecurityException Failed to generate the certificate
     *             request.
     */
    public static String createCertificateRequest(X509Certificate subjectCert, String sigAlgName, KeyPair keyPair)
            throws GeneralSecurityException {

        PKCS10CertificationRequest certRequest = new PKCS10CertificationRequest(sigAlgName,
                subjectCert.getSubjectX500Principal(), keyPair.getPublic(), null, keyPair.getPrivate());

        StringWriter stringWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(stringWriter);
        try {
            pemWriter.writeObject(certRequest);
            pemWriter.flush();
        } catch (IOException e) {
            throw new GeneralSecurityException("Certificate output as string failed: " + e.getMessage());
        } finally {
            try {
                pemWriter.close();
            } catch (IOException e) {
                // should not happen, and doesn't matter anyway.
            }
        }

        return stringWriter.toString();
    }

    /**
     * Generate a new key pair.
     * 
     * @return The generated KeyPair object.
     */
    public static KeyPair getKeyPair(int size) {

        SecureRandom rand = new SecureRandom();
        JDKKeyPairGenerator.RSA keyPairGen = new JDKKeyPairGenerator.RSA();
        keyPairGen.initialize(size, rand);
        return keyPairGen.generateKeyPair();
    }

    /**
     * Generates a new session ID based on the public key.
     * 
     * @param pk public key of a certificate (request)
     * @return The generated session ID
     */
    public static String generateSessionID(PublicKey pk) throws java.security.NoSuchAlgorithmException {
        return new String(Hex.encode(getMostSignificant(digest(pk.getEncoded()), 20)));

    }

    /**
     * Generates a new delegation ID starting from the given DN and list of VOMS
     * attributes.
     * 
     * @param dn The dn to be used in the hashing process.
     * @param vomsAttributes The list of attributes to be used in the hashing
     *            process.
     * @return The generated delegation ID.
     */
    public static String genDlgID(String dn, String[] vomsAttributes) {

        String originalString = dn;
        if (vomsAttributes != null) {
            for (int i = 0; i < vomsAttributes.length; i++) {
                originalString += vomsAttributes[i];
            }
        } else {
            LOGGER.debug("No VOMS attributes in client certificate. Generating DLG ID using" + "only the client DN.");
        }

        byte origStringB[] = originalString.getBytes();
        byte digest[] = digest(origStringB);
        byte mostSigni[] = getMostSignificant(digest, 20);
        byte hexEnc[] = Hex.encode(mostSigni);
        String digestString = new String(hexEnc);

        // String digestString = new
        // String(Hex.encode(getMostSignificant(digest(originalString.getBytes()),
        // 20)));
        LOGGER.debug("Digest VOMS Attributes: " + digestString);

        return digestString;

    }

    /**
     * Returns the list of VOMS attributes exposed in the given SecurityContext.
     * 
     * @param sc The SecurityContext object from which to take the attributes
     * @return A String list containing the attributes. Empty (0 element) array
     *         if no attributes.
     * @deprecated use the method getVomsAttributes in the GliteDelegation that does the validation properly and is configurable.
     */
    public static String[] getVOMSAttributes(X509Certificate certs[]) {
        if (vomsValidator == null){
            vomsValidator = VOMSValidators.newValidator();
        }
        List<VOMSAttribute> attributeCerts = vomsValidator.validate(certs);
        ArrayList<String> attributes = new ArrayList<String>();
        
        for(VOMSAttribute attributeCert:attributeCerts){
            if(attributeCert != null){
                List<String> theseAttributes = attributeCert.getFQANs();
                if(theseAttributes != null){
                    attributes.addAll(theseAttributes);
                }
            }
        }
        return attributes.toArray(new String[attributes.size()]);
    }

    /**
     * Returns a single string representation of the VOMS attributes list.
     * 
     * @param vomsAttributes The VOMS attributes array
     * @return A single string representation of the VOMS attributes list
     */
    public static String toStringVOMSAttrs(String[] vomsAttributes) {
        if (vomsAttributes == null) {
            return "";
        }

        String vomsAttrsStr = "";
        for (int i = 0; i < vomsAttributes.length; i++) {
            vomsAttrsStr += "\t" + vomsAttributes[i];
        }

        return vomsAttrsStr;
    }

    /**
     * Returns the list of VOMS attributes from a single string representation.
     * 
     * @param vomsAttributesStr A single string representation of a VOMS
     *            attributes list.
     * @return A string array containing the VOMS attributes
     */
    public static String[] fromStringVOMSAttrs(String vomsAttributesStr) {
        if (vomsAttributesStr == null) {
            return new String[0];
        }

        StringTokenizer st = new StringTokenizer("\t");
        ArrayList<String> vomsAttributes = new ArrayList<String>();

        while (st.hasMoreTokens()) {
            vomsAttributes.add(st.nextToken());
        }

        return (String[]) vomsAttributes.toArray(new String[] {});
    }


}
