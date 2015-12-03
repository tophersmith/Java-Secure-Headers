package topher.smith.security.headers.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

import topher.smith.security.headers.util.InvalidHeaderException;

public class XContentTypeOptionsHeaderTest {

	@Test
	public void testValidate() {
		XContentTypeOptionsHeader cont = new XContentTypeOptionsHeader();
		try {
			cont.validate();
		} catch (InvalidHeaderException e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testBuildHeaderValue() {
		XContentTypeOptionsHeader cont = new XContentTypeOptionsHeader();
		assertEquals(null,cont.buildHeaderValue(), "nosniff");
	}
}
