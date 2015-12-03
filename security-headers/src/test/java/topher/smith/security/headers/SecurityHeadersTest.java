package topher.smith.security.headers;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Map.Entry;

import org.junit.Before;
import org.junit.Test;

import topher.smith.security.headers.impl.XFrameOptionsHeader;
import topher.smith.security.headers.impl.XXSSProtectionHeader;

public class SecurityHeadersTest{
	private XFrameOptionsHeader xframe;
	private XXSSProtectionHeader xss;
	
	@Before
	public void setUp(){
		xframe = new XFrameOptionsHeader();
		xss = new XXSSProtectionHeader();
	}
	
	private SecurityHeaders basicSetup(){
		SecurityHeaders head = new SecurityHeaders();
		xframe.setDeny();
		xss.enableBlock().enableProtection();
		head.addHeader(xframe).addHeader(xss);
		return head;
	}
	
	@Test
	public void testSecurityHeadersStandard() {
		SecurityHeaders head = basicSetup();
		List<String> reports = head.validateAllHeaders();
		assertTrue(reports == null);
		List<String> headers = head.buildHeaderLines();
		assertTrue(headers.toString().contains(xss.getHeaderName()));
		assertTrue(headers.toString().contains(xframe.getHeaderName()));
	}
	
	@Test
	public void testSecurityHeadersEntries() {
		SecurityHeaders head = basicSetup();
		List<String> reports = head.validateAllHeaders();
		assertTrue(reports == null);
		List<Entry<String, String>> headers = head.buildHeaders();
		for(Entry<String,String> entry : headers){
			if(entry.getKey().equals(xss.getHeaderName())){
				assertEquals(xss.buildHeaderValue(), entry.getValue());
			} else if(entry.getKey().equals(xframe.getHeaderName())){
				assertEquals(xframe.buildHeaderValue(),entry.getValue());
			} else{
				fail("Could not get xframe or xss header for entry: " + entry.toString());
			}
		}
	}
	
	@Test
	public void testBadCharacters(){
		SecurityHeaders head = basicSetup();
		String origin = "http://foo.com\n";
		xframe.setAllowFrom(origin);
		List<Entry<String, String>> headers = head.buildHeaders();
		for(Entry<String,String> entry : headers){
			if(entry.getKey().equals(xframe.getHeaderName())){
				assertTrue(!entry.getValue().contains("\n"));
			}
		}
	}
	
	@Test
	public void testValidationErrors(){
		SecurityHeaders head = basicSetup();
		String origin = "this is not an origin";
		xframe.setAllowFrom(origin);
		List<String> reports = head.validateAllHeaders();
		assertTrue(reports != null);
		assertTrue(reports.size() == 1);
		assertEquals("When using Allow-From, a valid origin must be set",reports.get(0));
	}
}
