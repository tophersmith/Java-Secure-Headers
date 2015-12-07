package com.github.tophersmith.security.headers.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import com.github.tophersmith.security.headers.impl.XFrameOptionsHeader;
import com.github.tophersmith.security.headers.util.InvalidHeaderException;

public class XFrameOptionsHeaderTest {
	private final static String REPORT_URL = "http://foo.com";
	private final static String BAD_REPORT_URL = "http:/foo.com";

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
		xf.setAllowFrom(XFrameOptionsHeaderTest.REPORT_URL);
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
		xf.setAllowFrom(XFrameOptionsHeaderTest.BAD_REPORT_URL);
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
		assertEquals("DENY", xf.buildHeaderValue());
		xf.setAllowFrom(XFrameOptionsHeaderTest.REPORT_URL);
		assertEquals("ALLOW-FROM " + XFrameOptionsHeaderTest.REPORT_URL, xf.buildHeaderValue());
	}
	
	@Test
	public void testBuildHeaderDefault() {
		XFrameOptionsHeader xf = new XFrameOptionsHeader();
		assertEquals("SAMEORIGIN",xf.buildHeaderValue());
	}

}
