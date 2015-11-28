/*
 * Copyright 2015 Christopher Smith
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
