package tophersmith.security.headers.csp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import tophersmith.security.headers.csp.directives.AbstractCSPDirective;
import tophersmith.security.headers.csp.directives.impl.BaseUriDirective;
import tophersmith.security.headers.csp.directives.impl.ChildSrcDirective;
import tophersmith.security.headers.csp.directives.impl.ConnectSrcDirective;
import tophersmith.security.headers.csp.directives.impl.DefaultSrcDirective;
import tophersmith.security.headers.csp.directives.impl.ExperimentalDirective;
import tophersmith.security.headers.csp.directives.impl.FontSrcDirective;
import tophersmith.security.headers.csp.directives.impl.FormActionDirective;
import tophersmith.security.headers.csp.directives.impl.FrameAncestorsDirective;
import tophersmith.security.headers.csp.directives.impl.FrameSrcDirective;
import tophersmith.security.headers.csp.directives.impl.ImgSrcDirective;
import tophersmith.security.headers.csp.directives.impl.MediaSrcDirective;
import tophersmith.security.headers.csp.directives.impl.ObjectSrcDirective;
import tophersmith.security.headers.csp.directives.impl.PluginTypesDirective;
import tophersmith.security.headers.csp.directives.impl.ReportUriDirective;
import tophersmith.security.headers.csp.directives.impl.SandboxDirective;
import tophersmith.security.headers.csp.directives.impl.ScriptSrcDirective;
import tophersmith.security.headers.csp.directives.impl.StyleSrcDirective;

public class DirectivesTest {
	private final List<String> goodSource = new ArrayList<String>();
	private final List<String> badSource = new ArrayList<String>();
	private static final String BASIC_SOURCE = "http://www.foo.com";
	
	@Before
	public void setUp() throws Exception {
		this.goodSource.add("http:");
		this.goodSource.add("*");
		this.goodSource.add("http://foo.com/bar.html");
		this.goodSource.add("http://foo.com/bar");
		this.goodSource.add("https:");
		this.goodSource.add("https://*.foo.com");
		this.goodSource.add("http://111.12.32.132");
		this.goodSource.add("129.31.232.132");
		
		this.badSource.add("http:\\\\foo.com\\bar");
		this.badSource.add("http://;");
		this.badSource.add("https://*.,foo.com");
		this.badSource.add("https://*. foo.com");
	}
	
	private void directiveTest(AbstractCSPDirective dir, String directiveName, 
			int numValues, boolean validationShouldHaveErrors, String...buildShouldContain){
		CSPValidationReport report = new CSPValidationReport();
		if(buildShouldContain != null){
			for(String s : buildShouldContain){
				assertTrue(dir.buildDirective().contains(s));
			}
		}
		assertTrue(dir.getDirectiveName().equals(directiveName));
		assertTrue(dir.getDirectiveValues().size() == numValues);
		dir.validateAndReport(report);
		assertTrue(report.getErrorReports().toString(), report.isErrorsEmpty() == !validationShouldHaveErrors);
	}
	
	@Test
	public void testBaseUri() {
		String name = "base-uri";
		BaseUriDirective dir = new BaseUriDirective();
		dir.addSelf();
		dir.addNone();
		dir.addSource(BASIC_SOURCE);
		for(String src : this.goodSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.goodSource.size()+3, false, BASIC_SOURCE, "'self'", "'none'");
		for(String src : this.badSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.badSource.size()+this.goodSource.size()+3, true, BASIC_SOURCE, "'self'", "'none'");
	}
	
	@Test
	public void testChildSrc() {
		String name = "child-src";
		ChildSrcDirective dir = new ChildSrcDirective();
		dir.addSelf();
		dir.addNone();
		dir.addSource(BASIC_SOURCE);
		for(String src : this.goodSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.goodSource.size()+3, false, BASIC_SOURCE, "'self'", "'none'");
		for(String src : this.badSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.badSource.size()+this.goodSource.size()+3, true, BASIC_SOURCE, "'self'", "'none'");
	}

	@Test
	public void testConnectSrc() {
		String name = "connect-src";
		ConnectSrcDirective dir = new ConnectSrcDirective();
		dir.addSelf();
		dir.addNone();
		dir.addSource(BASIC_SOURCE);
		for(String src : this.goodSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.goodSource.size()+3, false, BASIC_SOURCE, "'self'", "'none'");
		for(String src : this.badSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.badSource.size()+this.goodSource.size()+3, true, BASIC_SOURCE, "'self'", "'none'");
	}

	@Test
	public void testDefaultSrc() {
		String name = "default-src";
		DefaultSrcDirective dir = new DefaultSrcDirective();
		dir.addSelf();
		dir.addNone();
		dir.addSource(BASIC_SOURCE);
		for(String src : this.goodSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.goodSource.size()+3, false, BASIC_SOURCE, "'self'", "'none'");
		for(String src : this.badSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.badSource.size()+this.goodSource.size()+3, true, BASIC_SOURCE, "'self'", "'none'");
	}

	@Test
	public void testFontSrc() {
		String name = "font-src";
		FontSrcDirective dir = new FontSrcDirective();
		dir.addSelf();
		dir.addNone();
		dir.addSource(BASIC_SOURCE);
		for(String src : this.goodSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.goodSource.size()+3, false, BASIC_SOURCE, "'self'", "'none'");
		for(String src : this.badSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.badSource.size()+this.goodSource.size()+3, true, BASIC_SOURCE, "'self'", "'none'");
	}

	@Test
	public void testFormAction() {
		String name = "form-action";
		FormActionDirective dir = new FormActionDirective();
		dir.addSelf();
		dir.addNone();
		dir.addSource(BASIC_SOURCE);
		for(String src : this.goodSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.goodSource.size()+3, false, BASIC_SOURCE, "'self'", "'none'");
		for(String src : this.badSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.badSource.size()+this.goodSource.size()+3, true, BASIC_SOURCE, "'self'", "'none'");
	}

	@Test
	public void testFrameAncestors() {
		String name = "frame-ancestors";
		FrameAncestorsDirective dir = new FrameAncestorsDirective();
		dir.addSelf();
		dir.addNone();
		dir.addSource(BASIC_SOURCE);
		for(String src : this.goodSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.goodSource.size()+3, false, BASIC_SOURCE, "'self'", "'none'");
		for(String src : this.badSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.badSource.size()+this.goodSource.size()+3, true, BASIC_SOURCE, "'self'", "'none'");
	}
	
	@Test
	public void testFrameSrc() {
		String name = "frame-src";
		FrameSrcDirective dir = new FrameSrcDirective();
		dir.addSelf();
		dir.addNone();
		dir.addSource(BASIC_SOURCE);
		for(String src : this.goodSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.goodSource.size()+3, false, BASIC_SOURCE, "'self'", "'none'");
		for(String src : this.badSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.badSource.size()+this.goodSource.size()+3, true, BASIC_SOURCE, "'self'", "'none'");
	}

	@Test
	public void testImgSrc() {
		String name = "img-src";
		ImgSrcDirective dir = new ImgSrcDirective();
		dir.addSelf();
		dir.addNone();
		dir.addSource(BASIC_SOURCE);
		for(String src : this.goodSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.goodSource.size()+3, false, BASIC_SOURCE, "'self'", "'none'");
		for(String src : this.badSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.badSource.size()+this.goodSource.size()+3, true, BASIC_SOURCE, "'self'", "'none'");
	}

	@Test
	public void testMediaSrc() {
		String name = "media-src";
		MediaSrcDirective dir = new MediaSrcDirective();
		dir.addSelf();
		dir.addNone();
		dir.addSource(BASIC_SOURCE);
		for(String src : this.goodSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.goodSource.size()+3, false, BASIC_SOURCE, "'self'", "'none'");
		for(String src : this.badSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.badSource.size()+this.goodSource.size()+3, true, BASIC_SOURCE, "'self'", "'none'");
	}

	@Test
	public void testObjectSrc() {
		String name = "object-src";
		ObjectSrcDirective dir = new ObjectSrcDirective();
		dir.addSelf();
		dir.addNone();
		dir.addSource(BASIC_SOURCE);
		for(String src : this.goodSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.goodSource.size()+3, false, BASIC_SOURCE, "'self'", "'none'");
		for(String src : this.badSource){
			dir.addSource(src);
		}
		directiveTest(dir, name, this.badSource.size()+this.goodSource.size()+3, true, BASIC_SOURCE, "'self'", "'none'");
	}

	@Test
	public void testPluginTypes() {
		String name = "plugin-types";
		PluginTypesDirective dir = new PluginTypesDirective();
		dir.addMediaType("application/media");
		directiveTest(dir, name, 1, false, "application/media");
		dir.addMediaType("foobar");
		directiveTest(dir, name, 2, true, "application/media");
		
	}
	
	@Test
	public void testReportUri() {
		String name = "report-uri";
		ReportUriDirective dir = new ReportUriDirective();
		dir.addReportUri(BASIC_SOURCE);
		directiveTest(dir, name, 1, false, BASIC_SOURCE);
		dir.addReportUri(this.badSource.get(0));
		directiveTest(dir, name, 2, true, BASIC_SOURCE);
	}
	
	@Test
	public void testSandbox() {
		String name = "sandbox";
		SandboxDirective dir = new SandboxDirective();
		dir.addAllowForms().addAllowPointerLock().addAllowPopups()
			.addAllowSameOrigin().addAllowScripts().addAllowTopNavigation();
		directiveTest(dir, name, 6, false, "allow-forms", "allow-pointer-lock", 
				"allow-popups", "allow-same-origin", "allow-scripts", "allow-top-navigation");
	}
	
	@Test
	public void testScriptSrc() {
		String name = "script-src";
		ScriptSrcDirective dir = new ScriptSrcDirective();
		
		dir.addSelf();
		dir.addNone();
		dir.addSource(BASIC_SOURCE);
		dir.addUnsafeEval();
		dir.addUnsafeInline();
		for(String src : this.goodSource){
			dir.addSource(src);
		}
		for(int i = 0; i < 2; i++){
			String nonce = ScriptSrcDirective.generateNonce(10);
			String hash = "QUFB";
			
			dir.addNonce(nonce);
			dir.addHash("sha256", hash);
		}
		directiveTest(dir, name, this.goodSource.size()+5, false, BASIC_SOURCE, "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "QUFB", "sha256");
		
		dir.resetHashes();
		dir.resetNonces();
		
		directiveTest(dir, name, this.goodSource.size()+5, false, BASIC_SOURCE, "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'");
		
		assertTrue(!dir.buildDirective().contains("sha256"));
		assertTrue(!dir.buildDirective().contains("QUFB"));

		for(String src : this.badSource){
			dir.addSource(src);
		}

		for(int i = 0; i < 2; i++){
			String nonce = ScriptSrcDirective.generateNonce(10);
			String hash = "QUFB";
			
			dir.addNonce(nonce);
			dir.addHash("sha512", hash);
		}
		directiveTest(dir, name, this.badSource.size()+this.goodSource.size()+5, true, BASIC_SOURCE, "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "QUFB", "sha512");
	}
	
	@Test
	public void testStyleSrc() {
		String name = "style-src";
		StyleSrcDirective dir = new StyleSrcDirective();
		
		dir.addSelf();
		dir.addNone();
		dir.addSource(BASIC_SOURCE);
		dir.addUnsafeEval();
		dir.addUnsafeInline();
		for(String src : this.goodSource){
			dir.addSource(src);
		}
		for(int i = 0; i < 2; i++){
			String nonce = StyleSrcDirective.generateNonce(10);
			String hash = "QUFB";
			
			dir.addNonce(nonce);
			dir.addHash("sha256", hash);
		}
		directiveTest(dir, name, this.goodSource.size()+5, false, BASIC_SOURCE, "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "QUFB", "sha256");
		
		dir.resetHashes();
		dir.resetNonces();
		
		directiveTest(dir, name, this.goodSource.size()+5, false, BASIC_SOURCE, "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'");
		
		assertTrue(!dir.buildDirective().contains("sha256"));
		assertTrue(!dir.buildDirective().contains("QUFB"));

		for(String src : this.badSource){
			dir.addSource(src);
		}

		for(int i = 0; i < 2; i++){
			String nonce = StyleSrcDirective.generateNonce(10);
			String hash = "QUFB";
			
			dir.addNonce(nonce);
			dir.addHash("sha512", hash);
		}
		directiveTest(dir, name, this.badSource.size()+this.goodSource.size()+5, true, BASIC_SOURCE, "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "QUFB", "sha512");
	}
	
	@Test
	public void testExperimentalDirectives(){
		String dirName = "x-csp-directive";
		String badExpValue = "x-dir:val;'(#ue";
		String goodExpValue = "x-dir:value";
		ExperimentalDirective exp = new ExperimentalDirective(dirName);
		exp.addExperimentalValue(badExpValue);
		directiveTest(exp, dirName, 1, true, badExpValue);
		
		ExperimentalDirective exp2 = new ExperimentalDirective(dirName);
		exp2.addExperimentalValue(goodExpValue);
		directiveTest(exp2, dirName, 1, false, goodExpValue);
		
		
		DefaultSrcDirective def = new DefaultSrcDirective();
		def.addSelf().addExperimentalValue(badExpValue);
		directiveTest(def, DefaultSrcDirective.NAME, 2, true, badExpValue);
		
		DefaultSrcDirective def2 = new DefaultSrcDirective();
		def2.addSelf().addExperimentalValue(goodExpValue);
		directiveTest(def2, DefaultSrcDirective.NAME, 2, false, goodExpValue);
	}
	
	@Test
	public void testBadDefinitions(){
		DefaultSrcDirective def = new DefaultSrcDirective();
		def.addSource("");
		def.addSource(null);
		directiveTest(def, "default-src", 0, false);
		
		ScriptSrcDirective script = new ScriptSrcDirective();
		script.addHash("foobar", "");
		script.addHash("sha-256", null);
		script.addHash(null, null);
		script.addNonce(null);
		directiveTest(script, "script-src", 0, true);
		
		FrameSrcDirective frame = new FrameSrcDirective();
		frame.addSource(this.badSource.get(0));
		directiveTest(frame, "frame-src", 1, true);
		
		ChildSrcDirective child = new ChildSrcDirective();
		assertEquals("", child.buildDirective());
	}
}
