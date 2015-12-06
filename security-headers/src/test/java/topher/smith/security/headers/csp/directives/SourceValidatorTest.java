package topher.smith.security.headers.csp.directives;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.apache.commons.validator.routines.UrlValidator;
import org.junit.Test;

public class SourceValidatorTest {

	@Test
	public void testValidCharacters() {
		String[] positiveTests = new String[]{"A", "1", ":", "A1:"};
		String[] negativeTests = new String[]{" ", ";", ",", "A ;,", null};
		for(String value : positiveTests){
			assertTrue(value + "failed", SourceValidator.hasValidCharacters(value));
		}
		for(String value : negativeTests){
			assertFalse(value + "failed", SourceValidator.hasValidCharacters(value));
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
			assertTrue(value + "failed", SourceValidator.isValidHostSource(value));
		}
		for(String value : negativeTests){
			assertFalse(value + "failed", SourceValidator.isValidHostSource(value));
		}
	}
	
	@Test
	public void testValidScheme() {
		String[] positiveTests = new String[]{"http:", "https:", "data:", 
				"fake:", "averylongscheme:", "chars+.-:"};
		String[] negativeTests = new String[]{":", "4:","&^%$#:", "", null};
		for(String value : positiveTests){
			assertTrue(value + "failed", SourceValidator.isValidSchemeSource(value));
		}
		for(String value : negativeTests){
			assertFalse(value + "failed", SourceValidator.isValidSchemeSource(value));
		}
	}
	
	@Test
	public void testValidKeywords() {
		String[] positiveTests = new String[]{ "'none'", "'self'"};
		String[] negativeTests = new String[]{"*", "foo", null, "'no'"};
		for(String value : positiveTests){
			assertTrue(value + "failed", SourceValidator.isValidSrcKeyword(value));
		}
		for(String value : negativeTests){
			assertFalse(value + "failed", SourceValidator.isValidSrcKeyword(value));
		}
	}
	
	@Test
	public void testValidUnsafe() {
		String[] positiveTests = new String[]{"'unsafe-inline'", "'unsafe-eval'"};
		String[] negativeTests = new String[]{"'unsafe-foobar'", null};
		for(String value : positiveTests){
			assertTrue(value + "failed", SourceValidator.isValidUnsafeKeyword(value));
		}
		for(String value : negativeTests){
			assertFalse(value + "failed", SourceValidator.isValidUnsafeKeyword(value));
		}
	}
	
	@Test
	public void test(){
		UrlValidator.getInstance().isValid("http://foo.com:32/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/?a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/aX");
	}
}
