package securityheaders.csp;

import java.util.Arrays;
import java.util.List;

import securityheaders.csp.directives.impl.BaseUriDirective;
import securityheaders.csp.directives.impl.ChildSrcDirective;
import securityheaders.csp.directives.impl.ConnectSrcDirective;
import securityheaders.csp.directives.impl.DefaultSrcDirective;
import securityheaders.csp.directives.impl.FontSrcDirective;
import securityheaders.csp.directives.impl.FormActionDirective;
import securityheaders.csp.directives.impl.FrameAncestorsDirective;
import securityheaders.csp.directives.impl.FrameSrcDirective;
import securityheaders.csp.directives.impl.ImgSrcDirective;
import securityheaders.csp.directives.impl.MediaSrcDirective;
import securityheaders.csp.directives.impl.ObjectSrcDirective;
import securityheaders.csp.directives.impl.PluginTypesDirective;
import securityheaders.csp.directives.impl.ReportUriDirective;
import securityheaders.csp.directives.impl.SandboxDirective;
import securityheaders.csp.directives.impl.ScriptSrcDirective;
import securityheaders.csp.directives.impl.StyleSrcDirective;

public enum PolicyLevel{
	CSP1(new String[]{ConnectSrcDirective.NAME, 	DefaultSrcDirective.NAME, 	FontSrcDirective.NAME,
					  FrameSrcDirective.NAME, 		ImgSrcDirective.NAME, 		MediaSrcDirective.NAME, 
					  ObjectSrcDirective.NAME, 		ReportUriDirective.NAME, 	SandboxDirective.NAME,
					  ScriptSrcDirective.NAME, 		StyleSrcDirective.NAME},
		new String[]{}), 
	
	CSP2(new String[]{BaseUriDirective.NAME, 		ChildSrcDirective.NAME, 	ConnectSrcDirective.NAME, 
					  DefaultSrcDirective.NAME, 	FontSrcDirective.NAME,		FormActionDirective.NAME,
					  FrameAncestorsDirective.NAME, FrameSrcDirective.NAME, 	ImgSrcDirective.NAME,
					  MediaSrcDirective.NAME, 		ObjectSrcDirective.NAME, 	PluginTypesDirective.NAME,
					  ReportUriDirective.NAME,		SandboxDirective.NAME, 		ScriptSrcDirective.NAME, 
					  StyleSrcDirective.NAME},
		 new String[]{FrameSrcDirective.NAME}),
	;
	
	private final List<String> allowedNames;
	private final List<String> deprecatedNames;
	
	private PolicyLevel(String[] allowedNames, String[] deprecatedNames){
		this.allowedNames = Arrays.asList(allowedNames);
		this.deprecatedNames = Arrays.asList(deprecatedNames);
	}
	
	boolean isAllowed(String directiveName){
		return this.allowedNames.contains(directiveName);
	}
	
	boolean isDeprecated(String directiveName){
		return this.deprecatedNames.contains(directiveName);
	}
}
