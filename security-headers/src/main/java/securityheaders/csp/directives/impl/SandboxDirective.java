package securityheaders.csp.directives.impl;

import securityheaders.csp.CSPValidationReport;
import securityheaders.csp.directives.AbstractCSPDirective;

public class SandboxDirective extends AbstractCSPDirective {

	public static final String NAME = "sandbox";

	private static final String FORMS = "allow-forms";
	private static final String POINTER_LOCK = "allow-pointer-lock";
	private static final String POPUPS = "allow-popups";
	private static final String SAME_ORIGIN = "allow-same-origin";
	private static final String SCRIPTS = "allow-scripts";
	private static final String TOP_NAV = "allow-top-navigation";

	public SandboxDirective() {
		super(SandboxDirective.NAME);
	}

	public SandboxDirective addAllowForms() {
		addDirectiveValue(SandboxDirective.FORMS);
		return this;
	}

	public SandboxDirective addAllowPointerLock() {
		addDirectiveValue(SandboxDirective.POINTER_LOCK);
		return this;
	}

	public SandboxDirective addAllowPopups() {
		addDirectiveValue(SandboxDirective.POPUPS);
		return this;
	}

	public SandboxDirective addAllowSameOrigin() {
		addDirectiveValue(SandboxDirective.SAME_ORIGIN);
		return this;
	}

	public SandboxDirective addAllowScripts() {
		addDirectiveValue(SandboxDirective.SCRIPTS);
		return this;
	}

	public SandboxDirective addAllowTopNavigation() {
		addDirectiveValue(SandboxDirective.TOP_NAV);
		return this;
	}

	@Override
	public void validateAndReport(CSPValidationReport report) {
		// this cannot be incorrect
	}

}
