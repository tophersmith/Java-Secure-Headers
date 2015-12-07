package tophersmith.security.headers.csp.directives;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import tophersmith.security.headers.util.Validator;

public class SourceValidatorTest {

	@Test
	public void testValidCharacters() {
		String[] positiveTests = new String[]{"A", "1", ":", "A1:"};
		String[] negativeTests = new String[]{" ", ";", ",", "A ;,", null};
		for(String value : positiveTests){
			assertTrue(value + "failed", Validator.hasValidCharacters(value));
		}
		for(String value : negativeTests){
			assertFalse(value + "failed", Validator.hasValidCharacters(value));
		}
	}
	
	@Test
	public void testValidHost() {
		String[] positiveTests = new String[]{"http://foo.com/bar.html", 
				"http://foo.com/bar", "https://*.foo.com", 
				"http://111.12.32.132", "129.31.232.132"};
		String[] negativeTests = new String[]{"http:\\\\foo.com\\bar", 
				"http://;",	"https://*.,foo.com", "https://*. foo.com", 
				"http://foo.com:789789/test", "http://foo.com:-4/test",
				"http://foo.com:hello/test", null};
		for(String value : positiveTests){
			assertTrue(value + "failed", Validator.isValidHostSource(value));
		}
		for(String value : negativeTests){
			assertFalse(value + "failed", Validator.isValidHostSource(value));
		}
	}
	
	@Test
	public void testValidScheme() {
		String[] positiveTests = new String[]{"http:", "https:", "data:", 
				"fake:", "averylongscheme:", "chars+.-:"};
		String[] negativeTests = new String[]{":", "4:","&^%$#:", "", null};
		for(String value : positiveTests){
			assertTrue(value + "failed", Validator.isValidSchemeSource(value));
		}
		for(String value : negativeTests){
			assertFalse(value + "failed", Validator.isValidSchemeSource(value));
		}
	}
	
	@Test
	public void testValidKeywords() {
		String[] positiveTests = new String[]{ "'none'", "'self'"};
		String[] negativeTests = new String[]{"*", "foo", null, "'no'"};
		for(String value : positiveTests){
			assertTrue(value + "failed", Validator.isValidSrcKeyword(value));
		}
		for(String value : negativeTests){
			assertFalse(value + "failed", Validator.isValidSrcKeyword(value));
		}
	}
	
	@Test
	public void testValidUnsafe() {
		String[] positiveTests = new String[]{"'unsafe-inline'", "'unsafe-eval'"};
		String[] negativeTests = new String[]{"'unsafe-foobar'", null};
		for(String value : positiveTests){
			assertTrue(value + "failed", Validator.isValidUnsafeKeyword(value));
		}
		for(String value : negativeTests){
			assertFalse(value + "failed", Validator.isValidUnsafeKeyword(value));
		}
	}
}
