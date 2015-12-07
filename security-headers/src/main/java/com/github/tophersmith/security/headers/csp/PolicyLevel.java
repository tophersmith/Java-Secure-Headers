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
package com.github.tophersmith.security.headers.csp;

import java.util.Arrays;
import java.util.List;

import com.github.tophersmith.security.headers.csp.directives.AbstractCSPDirective;
import com.github.tophersmith.security.headers.csp.directives.impl.BaseUriDirective;
import com.github.tophersmith.security.headers.csp.directives.impl.ChildSrcDirective;
import com.github.tophersmith.security.headers.csp.directives.impl.ConnectSrcDirective;
import com.github.tophersmith.security.headers.csp.directives.impl.DefaultSrcDirective;
import com.github.tophersmith.security.headers.csp.directives.impl.FontSrcDirective;
import com.github.tophersmith.security.headers.csp.directives.impl.FormActionDirective;
import com.github.tophersmith.security.headers.csp.directives.impl.FrameAncestorsDirective;
import com.github.tophersmith.security.headers.csp.directives.impl.FrameSrcDirective;
import com.github.tophersmith.security.headers.csp.directives.impl.ImgSrcDirective;
import com.github.tophersmith.security.headers.csp.directives.impl.MediaSrcDirective;
import com.github.tophersmith.security.headers.csp.directives.impl.ObjectSrcDirective;
import com.github.tophersmith.security.headers.csp.directives.impl.PluginTypesDirective;
import com.github.tophersmith.security.headers.csp.directives.impl.ReportUriDirective;
import com.github.tophersmith.security.headers.csp.directives.impl.SandboxDirective;
import com.github.tophersmith.security.headers.csp.directives.impl.ScriptSrcDirective;
import com.github.tophersmith.security.headers.csp.directives.impl.StyleSrcDirective;

/**
 * A helper enum, the PolicyLevel defines Allowed and Deprecated directives for
 * each level of CSP.
 * 
 * @author Chris Smith
 *
 */
public enum PolicyLevel{
	//Allowed array, deprecated array
	CSP1(new String[]{ConnectSrcDirective.NAME, 	DefaultSrcDirective.NAME, 	
					  FontSrcDirective.NAME,		FrameSrcDirective.NAME, 	
					  ImgSrcDirective.NAME, 		MediaSrcDirective.NAME, 
					  ObjectSrcDirective.NAME, 		ReportUriDirective.NAME, 	
					  SandboxDirective.NAME,		ScriptSrcDirective.NAME, 	
					  StyleSrcDirective.NAME},
		 new String[]{}), 
	
	CSP2(new String[]{BaseUriDirective.NAME, 		ChildSrcDirective.NAME, 	
					  ConnectSrcDirective.NAME,   	DefaultSrcDirective.NAME, 	
					  FontSrcDirective.NAME,		FormActionDirective.NAME,
					  FrameAncestorsDirective.NAME, FrameSrcDirective.NAME, 	
					  ImgSrcDirective.NAME,			MediaSrcDirective.NAME, 		
					  ObjectSrcDirective.NAME, 		PluginTypesDirective.NAME,
					  ReportUriDirective.NAME,		SandboxDirective.NAME, 		
					  ScriptSrcDirective.NAME, 		StyleSrcDirective.NAME},
		 new String[]{FrameSrcDirective.NAME}),
	;
	
	private final List<String> definedNames;
	private final List<String> deprecatedNames;
	
	private PolicyLevel(String[] definedNames, String[] deprecatedNames){
		this.definedNames = Arrays.asList(definedNames);
		this.deprecatedNames = Arrays.asList(deprecatedNames);
	}
	
	/**
	 * is the given directive defined for this policy level
	 * @param directive the directive to check for 
	 * @return true if the directive is defined for this level
	 */
	boolean isDefined(AbstractCSPDirective directive){
		return this.definedNames.contains(directive.getDirectiveName());
	}
	
	/**
	 * is the given directive in the deprecated array of directives
	 * @param directive the directive to check for 
	 * @return true if the directive is a deprecated directive
	 */
	boolean isDeprecated(AbstractCSPDirective directive){
		return this.deprecatedNames.contains(directive.getDirectiveName());
	}
}
