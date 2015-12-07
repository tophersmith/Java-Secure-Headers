package tophersmith.security.headers;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import tophersmith.security.headers.csp.SecurityHeadersCSPSuite;
import tophersmith.security.headers.csp.directives.SourceValidatorTest;
import tophersmith.security.headers.impl.SecurityHeadersImplSuite;

@RunWith(Suite.class)
@SuiteClasses({ SecurityHeadersTest.class, 
				SecurityHeadersCSPSuite.class, 
				SecurityHeadersImplSuite.class,
				SourceValidatorTest.class
				})
public class SecurityHeadersSuite {

}
