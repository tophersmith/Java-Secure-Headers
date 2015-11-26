package securityheaders.csp;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import securityheaders.csp.directives.AbstractCSPDirective;
import securityheaders.csp.directives.impl.ChildSrcDirective;
import securityheaders.csp.directives.impl.ConnectSrcDirective;
import securityheaders.csp.directives.impl.DefaultSrcDirective;
import securityheaders.csp.directives.impl.FontSrcDirective;
import securityheaders.csp.directives.impl.ImgSrcDirective;
import securityheaders.csp.directives.impl.MediaSrcDirective;
import securityheaders.csp.directives.impl.ObjectSrcDirective;
import securityheaders.csp.directives.impl.ScriptSrcDirective;
import securityheaders.csp.directives.impl.StyleSrcDirective;

public class ContentSecurityPolicy {

	private final Map<String, AbstractCSPDirective> directiveMap;
	private final CSPValidationReport validationReport;

	private static final String[] RELY_ON_DEFAULT = { ChildSrcDirective.NAME, ConnectSrcDirective.NAME,
			FontSrcDirective.NAME, ImgSrcDirective.NAME, MediaSrcDirective.NAME, ObjectSrcDirective.NAME,
			ScriptSrcDirective.NAME, StyleSrcDirective.NAME };

	public ContentSecurityPolicy() {
		this.directiveMap = new HashMap<String, AbstractCSPDirective>();
		this.validationReport = new CSPValidationReport();
	}

	// add to the map
	public ContentSecurityPolicy addDirective(AbstractCSPDirective directive) {
		this.directiveMap.put(directive.getDirectiveName(), directive);
		return this;
	}

	// remove duplicates from policy
	public ContentSecurityPolicy compress() {
		for (String key : this.directiveMap.keySet()) {
			AbstractCSPDirective directive = this.directiveMap.get(key);
			directive.removeInternalDuplicates();
		}

		if (this.directiveMap.containsKey(DefaultSrcDirective.NAME)) {
			DefaultSrcDirective defaultDir = (DefaultSrcDirective) this.directiveMap.get(DefaultSrcDirective.NAME);
			for (int i = 0; i < ContentSecurityPolicy.RELY_ON_DEFAULT.length; i++) {
				AbstractCSPDirective directive = this.directiveMap.get(ContentSecurityPolicy.RELY_ON_DEFAULT[i]);
				directive.removeDuplicatesOf(defaultDir);
			}
		} else {
			// TODO check for similarities in RELYONDEFAULT to make a default?
		}
		return this;
	}

	public void resetValidationReport() {
		this.validationReport.reset();
	}

	// validate all policy pieces
	public boolean isValid() {
		for (String key : this.directiveMap.keySet()) {
			AbstractCSPDirective directive = this.directiveMap.get(key);
			directive.validateAndReport(this.validationReport);
		}
		return this.validationReport.isErrorsEmpty();
	}

	// can return empty list
	public List<String> getValidationReports() {
		return this.validationReport.getErrorReports();
	}

	// return a string of the policy after removing invalid pieces
	public String build() {
		StringBuilder sb = new StringBuilder();
		for (String key : this.directiveMap.keySet()) {
			AbstractCSPDirective directive = this.directiveMap.get(key);
			sb.append(directive.buildDirective()).append("; ");
		}
		return sb.toString();
	}
}
