package topher.smith.security.headers.impl;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses({ ContentSecurityPolicyHeaderTest.class, 
				StrictTransportSecurityHeaderTest.class,
				XContentTypeOptionsHeaderTest.class, 
				XFrameOptionsHeaderTest.class, 
				XXSSProtectionHeaderTest.class })
public class SecurityHeadersImplSuite {

}
