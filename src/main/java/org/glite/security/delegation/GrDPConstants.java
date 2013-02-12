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

/**
 * Constants of GrDP delegation
 */
public abstract class GrDPConstants {
    public static final String NEWLINE = System.getProperty("line.separator");
    public static final String CNPROXY = "CN=proxy";

    /** @deprecated will be removed soon, as it's not used in delegation lib anymore */
    public static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256WithRSAEncryption";
    /** @deprecated don't use */
    public static String CRH = "-----BEGIN CERTIFICATE REQUEST-----";
    /** @deprecated don't use */
    public static String CRF = "-----END CERTIFICATE REQUEST-----";
    /** @deprecated don't use */
    public static String CH = "-----BEGIN CERTIFICATE-----";
    /** @deprecated don't use */
    public static String CF = "-----END CERTIFICATE-----";
    /** @deprecated don't use */
    public static String PRVH = "-----BEGIN RSA PRIVATE KEY-----";
    /** @deprecated don't use */
    public static String PRVF = "-----END RSA PRIVATE KEY-----";
}