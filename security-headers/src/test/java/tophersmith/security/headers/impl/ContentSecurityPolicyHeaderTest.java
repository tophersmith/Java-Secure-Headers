package tophersmith.security.headers.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import tophersmith.security.headers.csp.ContentSecurityPolicy;
import tophersmith.security.headers.csp.PolicyLevel;
import tophersmith.security.headers.csp.directives.impl.DefaultSrcDirective;
import tophersmith.security.headers.csp.directives.impl.FrameAncestorsDirective;
import tophersmith.security.headers.csp.directives.impl.FrameSrcDirective;
import tophersmith.security.headers.csp.directives.impl.SandboxDirective;
import tophersmith.security.headers.csp.directives.impl.ScriptSrcDirective;
import tophersmith.security.headers.impl.ContentSecurityPolicyHeader;
import tophersmith.security.headers.impl.ContentSecurityPolicyHeader.CSPHeaderName;
import tophersmith.security.headers.util.InvalidHeaderException;

public class ContentSecurityPolicyHeaderTest {

	private final static String BAD_SOURCE = "http:/foobar.com";
	private final static String SOURCE = "http://foobar.com";

	@Test
	public void testHeaderNames(){
		CSPHeaderName[] names = CSPHeaderName.values();
		for(int i = 0; i < names.length; i++){
			ContentSecurityPolicyHeader csp = new ContentSecurityPolicyHeader(names[i]);
			assertEquals(names[i].getPrimaryName(), csp.getHeaderName());
		}
		for(int i = 0; i < names.length; i++){
			ContentSecurityPolicyHeader csp = new ContentSecurityPolicyHeader(names[i], true);
			assertEquals(names[i].getReportName(), csp.getHeaderName());
		}
	}

	@Test
	public void testValidateBasic() {
		ContentSecurityPolicyHeader csp = new ContentSecurityPolicyHeader(CSPHeaderName.CSP);
		ContentSecurityPolicy policy = new ContentSecurityPolicy();
		policy.addDirective(new DefaultSrcDirective().addSelf());
		csp.setPolicy(policy);
		try {
			csp.validate();
		} catch (InvalidHeaderException e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testValidateInvalid() {
		ContentSecurityPolicyHeader csp = new ContentSecurityPolicyHeader(CSPHeaderName.CSP);
		ContentSecurityPolicy policy = new ContentSecurityPolicy();
		policy.addDirective(new DefaultSrcDirective().addSource(ContentSecurityPolicyHeaderTest.BAD_SOURCE));
		csp.setPolicy(policy);
		try {
			csp.validate();
		} catch (InvalidHeaderException e) {
			assertTrue(e.getMessage().contains("Source value " + ContentSecurityPolicyHeaderTest.BAD_SOURCE + " could not be validated"));
			assertTrue(csp.getValidationErrors().size() == 1);
		}
	}

	@Test
	public void testValidateInvalidPolicyLevels() {
		ContentSecurityPolicyHeader csp = new ContentSecurityPolicyHeader(CSPHeaderName.CSP);
		ContentSecurityPolicy policy = new ContentSecurityPolicy(PolicyLevel.CSP1);
		policy.addDirective(new FrameAncestorsDirective().addSelf());
		csp.setPolicy(policy);
		try {
			csp.validate();
			assertTrue(csp.getValidationWarnings().get(0).contains("does not define directive"));
		} catch (InvalidHeaderException e) {
			fail(e.getMessage());
		}
		ContentSecurityPolicy policy2 = new ContentSecurityPolicy(PolicyLevel.CSP2);
		policy2.addDirective(new FrameSrcDirective().addSelf());
		csp.setPolicy(policy2);
		try {
			csp.validate();
			assertTrue(csp.getValidationWarnings().get(0).contains("has deprecated directive"));
		} catch (InvalidHeaderException e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testWarnings() {
		ContentSecurityPolicyHeader csp = new ContentSecurityPolicyHeader(CSPHeaderName.CSP);
		ContentSecurityPolicy policy = new ContentSecurityPolicy();
		policy.addDirective(new DefaultSrcDirective().addSelf().addNone());
		csp.setPolicy(policy);
		try {
			csp.validate();
			assertTrue(csp.getValidationWarnings().size() == 1);
		} catch (InvalidHeaderException e) {
			fail(e.getMessage());
		}
	}

	@Test
	public void testNullPolicy() {
		ContentSecurityPolicyHeader csp = new ContentSecurityPolicyHeader(CSPHeaderName.CSP);
		try {
			csp.validate();
		} catch (InvalidHeaderException e) {
			assertTrue(e.getMessage().contains("must be set"));
		}
		assertEquals(null, csp.getValidationErrors());
		assertEquals(null, csp.getValidationWarnings());
		assertEquals(null, csp.buildHeaderValue());
	}

	@Test
	public void testCSPHeaderNames(){
		ContentSecurityPolicyHeader csp = new ContentSecurityPolicyHeader(CSPHeaderName.CSP);
		ContentSecurityPolicyHeader webkit = new ContentSecurityPolicyHeader(CSPHeaderName.WEBKIT);
		ContentSecurityPolicyHeader xcsp = new ContentSecurityPolicyHeader(CSPHeaderName.XCSP);
		ContentSecurityPolicy policy = new ContentSecurityPolicy();
		policy.addDirective(new DefaultSrcDirective().addSelf().addSource(ContentSecurityPolicyHeaderTest.SOURCE ));
		csp.setPolicy(policy);
		webkit.setPolicy(policy);
		xcsp.setPolicy(policy);
		assertEquals(csp.buildHeaderValue(), webkit.buildHeaderValue());
		assertEquals(webkit.buildHeaderValue(), xcsp.buildHeaderValue());
		
		ContentSecurityPolicyHeader csprep = new ContentSecurityPolicyHeader(CSPHeaderName.CSP, true);
		ContentSecurityPolicyHeader webkitrep = new ContentSecurityPolicyHeader(CSPHeaderName.WEBKIT, true);
		ContentSecurityPolicyHeader xcsprep = new ContentSecurityPolicyHeader(CSPHeaderName.XCSP, true);
		
		assertEquals(csp.getHeaderName()+"-Report-Only", csprep.getHeaderName());
		assertEquals(webkit.getHeaderName()+"-Report-Only", webkitrep.getHeaderName());
		assertEquals(xcsp.getHeaderName()+"-Report-Only", xcsprep.getHeaderName());
	}
	
	@Test
	public void testBuildHeaderValue() {
		ContentSecurityPolicyHeader csp = new ContentSecurityPolicyHeader(CSPHeaderName.CSP);
		ContentSecurityPolicy policy = new ContentSecurityPolicy();
		policy.addDirective(new DefaultSrcDirective().addSelf().addSource(ContentSecurityPolicyHeaderTest.SOURCE ));
		csp.setPolicy(policy);
		assertEquals("default-src 'self' " + ContentSecurityPolicyHeaderTest.SOURCE, csp.buildHeaderValue());
	}

	@Test
	public void testBuildHeaderValueNoReduce() {
		ContentSecurityPolicyHeader csp = new ContentSecurityPolicyHeader(CSPHeaderName.CSP);
		ContentSecurityPolicy policy = new ContentSecurityPolicy();
		policy.addDirective(new DefaultSrcDirective().addSelf().addSource("'self'"));
		csp.setPolicy(policy);
		assertEquals("default-src 'self' 'self'", csp.buildHeaderValue());
	}

	@Test
	public void testBuildHeaderValueReduce() {
		ContentSecurityPolicyHeader csp = new ContentSecurityPolicyHeader(CSPHeaderName.CSP);
		ContentSecurityPolicy policy = new ContentSecurityPolicy();
		policy.addDirective(new DefaultSrcDirective().addSelf().addNone());
		policy.addDirective(new SandboxDirective());
		csp.setPolicy(policy);
		csp.setReduce(true);
		assertEquals("default-src 'self' 'none'", csp.buildHeaderValue());
	}

	@Test
	public void testBuildHeaderValueReduceSanityCheck() {
		ContentSecurityPolicyHeader csp = new ContentSecurityPolicyHeader(CSPHeaderName.CSP);
		ContentSecurityPolicy policy = new ContentSecurityPolicy();
		policy.addDirective(new DefaultSrcDirective().addSelf().addNone());
		policy.addDirective(new ScriptSrcDirective().addSelf());
		csp.setPolicy(policy);
		String pre = csp.buildHeaderValue();
		csp.setReduce(true);
		assertEquals(pre, csp.buildHeaderValue());
	}
}
