package topher.smith.security.headers.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import topher.smith.security.headers.util.InvalidHeaderException;

public class XXSSProtectionHeaderTest {
	private final static String reportURL = "http://foo.com";
	private final static String badReportURL = "http:/foo.com";
	
	@Test
	public void testValidateStandard() {
		XXSSProtectionHeader xss = new XXSSProtectionHeader();
		try {
			xss.validate();
		} catch (InvalidHeaderException e) {
			fail(e.getMessage());
		}
	}
	
	@Test
	public void testValidateFullCorrect() {
		XXSSProtectionHeader xss = new XXSSProtectionHeader();
		xss.enableBlock().enableProtection().addReportURL(XXSSProtectionHeaderTest.reportURL);
		try {
			xss.validate();
		} catch (InvalidHeaderException e) {
			fail(e.getMessage());
		}
	}
	
	@Test
	public void testValidateBadURL() {
		XXSSProtectionHeader xss = new XXSSProtectionHeader();
		xss.enableBlock().enableProtection().addReportURL(XXSSProtectionHeaderTest.badReportURL);
		try {
			xss.validate();
		} catch (InvalidHeaderException e) {
			assertTrue(e.getMessage().contains("not a valid"));
		}
	}
	
	@Test
	public void testValidateBadProtectionBlock() {
		XXSSProtectionHeader xss = new XXSSProtectionHeader();
		xss.enableBlock().disableProtection().enableBlock();
		try {
			xss.validate();
		} catch (InvalidHeaderException e) {
			assertTrue(e.getMessage().contains("require mode=block"));
		}
	}
	
	@Test
	public void testValidatBadProtectionReport() {
		XXSSProtectionHeader xss = new XXSSProtectionHeader();
		xss.enableBlock().disableProtection().disableBlock().addReportURL(XXSSProtectionHeaderTest.reportURL);
		try {
			xss.validate();
		} catch (InvalidHeaderException e) {
			assertTrue(e.getMessage().contains("enable reporting"));
		}
	}
	
	@Test
	public void testValidateDisabled() {
		XXSSProtectionHeader xss = new XXSSProtectionHeader();
		xss.disableBlock().disableProtection();
		try {
			xss.validate();
		} catch (InvalidHeaderException e) {
			fail(e.getMessage());
		}
	}
	
	@Test
	public void testBuildHeaderStandard() {
		XXSSProtectionHeader xss = new XXSSProtectionHeader();
		assertEquals(null, xss.buildHeaderValue(), "1; mode=block");
	}
	
	@Test
	public void testBuildHeaderProtectionOnBlockOff() {
		XXSSProtectionHeader xss = new XXSSProtectionHeader();
		xss.disableBlock().enableProtection();
		assertEquals(null, xss.buildHeaderValue(), "1");
	}
	
	@Test
	public void testBuildHeaderProtectionOff() {
		XXSSProtectionHeader xss = new XXSSProtectionHeader();
		xss.disableBlock().disableProtection();
		assertEquals(null, xss.buildHeaderValue(), "0");
	}
	
	@Test
	public void testBuildHeaderFullCorrect() {
		XXSSProtectionHeader xss = new XXSSProtectionHeader();
		xss.enableBlock().enableProtection().addReportURL(XXSSProtectionHeaderTest.reportURL);
		assertEquals(null, xss.buildHeaderValue(),"1; mode=block; report="+XXSSProtectionHeaderTest.reportURL);
	}

}
