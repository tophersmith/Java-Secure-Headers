package topher.smith.security.headers;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import topher.smith.security.headers.csp.SecurityHeadersCSPSuite;
import topher.smith.security.headers.csp.directives.SourceValidatorTest;
import topher.smith.security.headers.impl.SecurityHeadersImplSuite;

@RunWith(Suite.class)
@SuiteClasses({ SecurityHeadersTest.class, 
				SecurityHeadersCSPSuite.class, 
				SecurityHeadersImplSuite.class,
				SourceValidatorTest.class
				})
public class SecurityHeadersSuite {

}
