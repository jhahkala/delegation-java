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

//import org.apache.log4j.Logger;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import java.util.Properties;

/**
 * Options manager for Delegatee (service) side
 */
public class GrDProxyDlgeeOptions {

    // The local logger object
    // private static Logger logger =
    // Logger.getLogger(GrDProxyDlgeeOptions.class);

    private String dlgeeDN = null;
    private String dlgeePass = null;
    private String delegationStorage = null;
    private String dlgeeStorageFactory = null;
    private String dlgeeStorageDbPool = null;
    private String proxyFile = null;
    private int dlgeeKeySize = -1;
    private boolean requireVomsAttributes = true;
    private String vomsDir = null;
    private String vomsCAs = null;
    private String revocationChecking = null;
    private String namespace = null;
    private String updateInterval = null;
    private boolean limited = false;

    /**
     * Returns whether the new proxy should be limited or not.
     * @return the limited
     */
    public boolean isLimited() {
        return limited;
    }

    /**
     * Sets whether the new proxy should be limited or not.
     * 
     * @param limited the limited to set
     */
    public void setLimited(boolean limited) {
        this.limited = limited;
    }

    /**
     * Constructor of class
     * 
     * @param filename file containing delegatee options
     */
    public GrDProxyDlgeeOptions(String filename) throws IOException {

        InputStream st = null;
        try {
            st = new FileInputStream(filename);
        } catch (FileNotFoundException e) {
            // fail silently, try resource next.

        }

        if (st == null) {
            st = GrDProxyDlgeeOptions.class.getClassLoader().getResourceAsStream(filename);
        }

        Properties props = new Properties();
        props.load(st);
        init(props);
    }

    /**
     * Constructor of class
     * 
     * @param props Properties object containing necessary values
     */
    public GrDProxyDlgeeOptions(Properties props) {
        init(props);
    }

    /**
     * The constructor of the class.
     */
    public GrDProxyDlgeeOptions() {
        // empty.
    }

    /**
     * Initializer
     */
    public void init(Properties props) {
        this.dlgeeDN = props.getProperty("dlgeeDN");

        this.dlgeePass = props.getProperty("dlgeePass");
        this.proxyFile = props.getProperty("proxyFile");
        this.delegationStorage = props.getProperty("delegationStorage");
        this.dlgeeStorageFactory = props.getProperty("dlgeeStorageFactory");
        this.dlgeeStorageDbPool = props.getProperty("dlgeeStorageDbPool");
        this.dlgeeKeySize = Integer.parseInt(props.getProperty("dlgeeKeySize"));
        String reqString = props.getProperty("requireVomsAttributes");
        if (reqString != null) {
            requireVomsAttributes = Boolean.parseBoolean(reqString);
        }
        this.vomsDir = props.getProperty("vomsDir");
        this.vomsCAs = props.getProperty("vomsCAs");
        this.revocationChecking = props.getProperty("revocationChecking");
        this.namespace = props.getProperty("namespace");
        this.updateInterval = props.getProperty("updateInterval");
        String limitedString = props.getProperty("limitedProxy");
        if(limitedString != null){
            this.limited = Boolean.parseBoolean(limitedString);
        }

    }

    /**
     * Getting delegatee's DN
     * 
     * @return the DN
     */
    public String getDlgeeDN() {
        return this.dlgeeDN;
    }

    /**
     * Getting delegatee's password
     * 
     * @return password assigned to delegatee
     */
    public String getDlgeePass() {
        return this.dlgeePass;
    }

    /**
     * Getting the name of proxy file
     * 
     * @return certificat proxy file name
     */
    public String getDlgeeProxyFile() {
        if (this.proxyFile == null)
            return (GrDPX509Util.getDefaultProxyFile());

        return this.proxyFile;
    }

    /**
     * Getting path to the storage of Proxy certificates
     * 
     * @return path to proxy certificates
     */
    public String getDlgeeStorage() {
        if (this.delegationStorage == null)
            return ("\tmp");

        return this.delegationStorage;
    }

    /**
     * Getting the type of Storage Type used by the DLGEE
     * 
     * @return type of Storage Type used by the DLGEE
     */
    public String getDlgeeStorageFactory() {
        return this.dlgeeStorageFactory;
    }

    /**
     * Getting the pool name of the db storage
     * 
     * @return pool name of the db storage
     */
    public String getDlgeeStorageDbPool() {
        return this.dlgeeStorageDbPool;
    }

    /**
     * Get the key size to be used
     * 
     * @return Key size to be used
     */
    public int getDlgeeKeySize() {
        return this.dlgeeKeySize;
    }

    /**
     * check whether the voms attributes are required or not.
     * 
     * @return whether the voms attributes are required.
     */
    public boolean isRequireVomsAttributes() {
        return requireVomsAttributes;
    }

    /**
     * setting delegatee's DN
     * 
     * @param dn DN
     */
    public void setDlgeeDN(String dn) {
        this.dlgeeDN = dn;
    }

    /**
     * setting delegatee's password
     * 
     * @param dgp delegatee password
     */
    public void setDlgeePass(String dgp) {
        this.dlgeePass = dgp;
    }

    /**
     * setting the name of proxy file
     * 
     * @param pf proxy file
     */
    public void setDlgeeProxyFile(String pf) {
        this.proxyFile = pf;
    }

    /**
     * setting path to the storage of Proxy certificates
     * 
     * @param stg storage
     */
    public void setDlgeeStorage(String stg) {
        this.delegationStorage = stg;
    }

    /**
     * Setting the storage type being used by the DLGEE
     * 
     * @param stgType storage type
     */
    public void setDlgeeStorageFactory(String stgType) {
        this.dlgeeStorageFactory = stgType;
    }

    /**
     * Setting the storage db pool name
     * 
     * @param stgDbPool storage pool name
     */
    public void setDlgeeStorageDbPool(String stgDbPool) {
        this.dlgeeStorageDbPool = stgDbPool;
    }

    /**
     * Setting generated delegation key size.
     * 
     * @param keySize the key size in bits
     */
    public void setDlgeeKeySize(int keySize) {
        this.dlgeeKeySize = keySize;
    }

    /**
     * Set whether VOMS attribute presence is required in the certificate chain that initializes the delegation process.
     * 
     * @param required true if voms attributes are required, false if lack of attributes is accepted as well as failure
     *            to extract the attributes. Default is true.
     */
    public void setRequireVomsAttributes(boolean required) {
        requireVomsAttributes = required;
    }

    /**
     * Gets the directory to get the lsc files from.
     * 
     * @return the vomsDir
     */
    public String getVomsDir() {
        return vomsDir;
    }

    /**
     * Sets the directory to get the lsc files from.
     * 
     * @param vomsDir the vomsDir to set
     */
    public void setVomsDir(String vomsDir) {
        this.vomsDir = vomsDir;
    }

    /**
     * Gets the directory where the CA files for checking the voms AC are loaded from.
     * 
     * @return the voms CA directory.
     */
    public String getVomsCAs() {
        return vomsCAs;
    }

    /**
     * Sets the directory where the CA files for checking the voms AC are loaded from.
     * 
     * @param vomsCAs the CA directory to set for voms certificate validation.
     */
    public void setVomsCAs(String vomsCAs) {
        this.vomsCAs = vomsCAs;
    }

    /**
     * @return the revocationChecking
     */
    public String getRevocationChecking() {
        return revocationChecking;
    }

    /**
     * @param revocationChecking the revocationChecking to set
     */
    public void setRevocationChecking(String revocationChecking) {
        this.revocationChecking = revocationChecking;
    }

    /**
     * @return the namespace
     */
    public String getNamespace() {
        return namespace;
    }

    /**
     * @param namespace the namespace to set
     */
    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    /**
     * @return the updateInterval
     */
    public String getUpdateInterval() {
        return updateInterval;
    }

    /**
     * @param updateInterval the updateInterval to set
     */
    public void setUpdateInterval(String updateInterval) {
        this.updateInterval = updateInterval;
    }
}
