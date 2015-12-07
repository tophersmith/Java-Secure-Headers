package tophersmith.security.headers.csp;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses({ DirectivesTest.class, 
				CSPValidationReportTest.class })
public class SecurityHeadersCSPSuite {

}
