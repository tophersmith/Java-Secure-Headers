package com.github.tophersmith.security.headers.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import com.github.tophersmith.security.headers.impl.XXSSProtectionHeader;
import com.github.tophersmith.security.headers.util.InvalidHeaderException;

public class XXSSProtectionHeaderTest {
	private final static String REPORT_URL = "http://foo.com";
	private final static String BAD_REPORT_URL = "http:/foo.com";
	
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
		xss.enableBlock().enableProtection().addReportURL(XXSSProtectionHeaderTest.REPORT_URL);
		try {
			xss.validate();
		} catch (InvalidHeaderException e) {
			fail(e.getMessage());
		}
	}
	
	@Test
	public void testValidateBadURL() {
		XXSSProtectionHeader xss = new XXSSProtectionHeader();
		xss.enableBlock().enableProtection().addReportURL(XXSSProtectionHeaderTest.BAD_REPORT_URL);
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
		xss.enableBlock().disableProtection().disableBlock().addReportURL(XXSSProtectionHeaderTest.REPORT_URL);
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
		assertEquals("1; mode=block", xss.buildHeaderValue());
	}
	
	@Test
	public void testBuildHeaderProtectionOnBlockOff() {
		XXSSProtectionHeader xss = new XXSSProtectionHeader();
		xss.disableBlock().enableProtection();
		assertEquals("1", xss.buildHeaderValue());
	}
	
	@Test
	public void testBuildHeaderProtectionOff() {
		XXSSProtectionHeader xss = new XXSSProtectionHeader();
		xss.disableBlock().disableProtection();
		assertEquals("0", xss.buildHeaderValue());
	}
	
	@Test
	public void testBuildHeaderFullCorrect() {
		XXSSProtectionHeader xss = new XXSSProtectionHeader();
		xss.enableBlock().enableProtection().addReportURL(XXSSProtectionHeaderTest.REPORT_URL);
		assertEquals("1; mode=block; report="+XXSSProtectionHeaderTest.REPORT_URL, xss.buildHeaderValue());
	}

}
