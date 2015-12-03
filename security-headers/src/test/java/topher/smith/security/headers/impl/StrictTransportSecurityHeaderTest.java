package topher.smith.security.headers.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import topher.smith.security.headers.util.InvalidHeaderException;

public class StrictTransportSecurityHeaderTest {

	@Test
	public void testValidateDefault() {
		StrictTransportSecurityHeader st = new StrictTransportSecurityHeader();
		try {
			st.validate();
		} catch (InvalidHeaderException e) {
			fail(e.getMessage());
		}
	}
	
	@Test
	public void testValidateFullComplete() {
		StrictTransportSecurityHeader st = new StrictTransportSecurityHeader();
		st.enableIncludeSubDomains().enablePreload().setMaxAge("0");
		try {
			st.validate();
		} catch (InvalidHeaderException e) {
			fail(e.getMessage());
		}
	}
	
	@Test
	public void testValidateMaxAgeBadValues() {
		StrictTransportSecurityHeader st = new StrictTransportSecurityHeader();
		st.setMaxAge("-10");
		try {
			st.validate();
		} catch (InvalidHeaderException e) {
			assertTrue(e.getMessage().contains("positive number or 0"));
		}
		st.setMaxAge("ASDS");
		try {
			st.validate();
		} catch (InvalidHeaderException e) {
			assertTrue(e.getMessage().contains("positive number or 0"));
		}
	}
	
	@Test
	public void testValidateMaxAgeNotSet() {
		StrictTransportSecurityHeader st = new StrictTransportSecurityHeader();
		st.setMaxAge("");
		try {
			st.validate();
		} catch (InvalidHeaderException e) {
			assertTrue(e.getMessage().contains("max-age must be set"));
		}
		st.setMaxAge(null);
		try {
			st.validate();
		} catch (InvalidHeaderException e) {
			assertTrue(e.getMessage().contains("max-age must be set"));
		}
	}
	
	@Test
	public void testBuildHeaderValueDefault() {
		StrictTransportSecurityHeader st = new StrictTransportSecurityHeader();
		assertEquals(null, st.buildHeaderValue(), "max-age=31536000; includeSubDomains");
	}
	
	@Test
	public void testBuildHeaderValueFullComplete() {
		StrictTransportSecurityHeader st = new StrictTransportSecurityHeader();
		st.enablePreload();
		assertEquals(null, st.buildHeaderValue(), "max-age=31536000; includeSubDomains; preload");
	}
	
	@Test
	public void testHeaderEquivalence() {
		StrictTransportSecurityHeader st = new StrictTransportSecurityHeader();
		st.disableIncludeSubDomains();
		String plain = st.buildHeaderValue();
		st.enableIncludeSubDomains();
		st.enablePreload();
		st.disableIncludeSubDomains();
		st.disablePreload();
		assertEquals(null, st.buildHeaderValue(), plain);
	}
}
