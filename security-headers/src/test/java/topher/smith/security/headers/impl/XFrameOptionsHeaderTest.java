package topher.smith.security.headers.impl;

import static org.junit.Assert.*;

import org.junit.Test;

import topher.smith.security.headers.util.InvalidHeaderException;

public class XFrameOptionsHeaderTest {
	private final String reportURL = "http://foo.com";
	private final String badReportURL = "http:/foo.com";

	@Test
	public void testValidateFullCorrect() {
		XFrameOptionsHeader xf = new XFrameOptionsHeader();
		xf.setSameOrigin();
		try {
			xf.validate();
		} catch (InvalidHeaderException e) {
			fail(e.getMessage());
		}
		xf.setDeny();
		try {
			xf.validate();
		} catch (InvalidHeaderException e) {
			fail(e.getMessage());
		}
		xf.setAllowFrom(this.reportURL);
		try {
			xf.validate();
		} catch (InvalidHeaderException e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testValidateDefault() {
		XFrameOptionsHeader xf = new XFrameOptionsHeader();
		try {
			xf.validate();
		} catch (InvalidHeaderException e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testValidateBadURL() {
		XFrameOptionsHeader xf = new XFrameOptionsHeader();
		xf.setAllowFrom(this.badReportURL);
		try {
			xf.validate();
		} catch (InvalidHeaderException e) {
			assertTrue(e.getMessage().contains("valid origin must be set"));
		}
	}
	
	

	@Test
	public void testBuildHeaderReporting() {
		XFrameOptionsHeader xf = new XFrameOptionsHeader();
		xf.setDeny();
		assertEquals(null, xf.buildHeaderValue(), "DENY");
		xf.setAllowFrom(this.reportURL);
		assertEquals(null, xf.buildHeaderValue(), "ALLOW-FROM " + this.reportURL);
	}
	
	@Test
	public void testBuildHeaderDefault() {
		XFrameOptionsHeader xf = new XFrameOptionsHeader();
		assertEquals(null, xf.buildHeaderValue(), "SAMEORIGIN");
	}

}
