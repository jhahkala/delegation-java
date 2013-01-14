package org.glite.security.delegation;

import org.glite.security.delegation.impl.GliteDelegation;

import junit.framework.TestCase;

public class DelegationTest  extends TestCase {
    
    public void testDelegation (){
        GrDProxyDlgeeOptions opts = new GrDProxyDlgeeOptions();
        opts.setDlgeeKeySize(2048);
        opts.setDlgeeProxyFile("src/test/certs/trusted_client.proxy.grid_proxy");
        opts.setDlgeeStorage("target");
        
        GliteDelegation delegation = new GliteDelegation(opts);
        
 //       String req = getProxyReq("testID", certs );
        
    }

}
