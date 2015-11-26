package securityheaders.csp.directives;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import securityheaders.csp.CSPValidationReport;

public abstract class AbstractCSPDirective {

	protected final List<String> directiveValues;
	protected final String name;

	public static final String SRC_KEY_NONE = "'none'";
	public static final String SRC_KEY_SELF = "'self'";
	public static final String SRC_UNSAFE_INLINE = "'unsafe-inline'";
	public static final String SRC_UNSAFE_EVAL = "'unsafe-eval'";

	private static final String[] ILLEGAL_SRC_CHARS = { " ", ";", "," };

	// 1 letter plus optional letters, digits, +, -, or .
	private static final String SCHEME_PART = "\\w{1}(?:[\\w\\d\\+\\-\\.])*";
	// * OR Optional *. plus 1 or more letters/digits plus optional . plus 1 or
	// more letters/digits
	private static final String HOST_PART = "(?:[*])|(?:(?:\\*\\.)?[\\w\\d]{1}(?:[\\.]?[\\d\\w])+)";
	// : followed by either 1 or more digits or *
	private static final String PORT_PART = ":(?:[\\d]+|\\*)";
	// a slash optionally followed by a non-slash character followed by any
	// characters
	private static final String PATH_PART = "(?:\\/(?:[^/][\\w\\d]*))+";
	private static final Pattern HOST_SOURCE = Pattern.compile("^" + // match
																		// start
																		// of
																		// string
	"(" + AbstractCSPDirective.SCHEME_PART + "://)?" + // scheme-part is optional
			"(" + AbstractCSPDirective.HOST_PART + ")" + // host-part is required
			"(" + AbstractCSPDirective.PORT_PART + ")?" + // port-part is optional
			"(" + AbstractCSPDirective.PATH_PART + ")?" + // path-part is optional
			"$");
	private static final Pattern SCHEME_SOURCE = Pattern.compile("^" + AbstractCSPDirective.SCHEME_PART + ":$");

	protected AbstractCSPDirective(String name) {
		this.name = name;
		this.directiveValues = new ArrayList<String>();
	}

	public String getDirectiveName() {
		return this.name;
	}

	protected void addDirectiveValue(String value) {
		if (value != null && !value.trim().isEmpty()) {
			this.directiveValues.add(value);
		}
	}

	protected void validateSourceListValue(String val, CSPValidationReport report) {
		String test = val.trim().toLowerCase();

		for (int i = 0; i < AbstractCSPDirective.ILLEGAL_SRC_CHARS.length; i++) {
			if (test.contains(AbstractCSPDirective.ILLEGAL_SRC_CHARS[i])) {
				report.addReport(this, "Source value " + val + " contains an illegal character: "
						+ AbstractCSPDirective.ILLEGAL_SRC_CHARS[i]);
				return;
			}
		}

		if (!test.equals(AbstractCSPDirective.SRC_KEY_SELF) && !test.equals(AbstractCSPDirective.SRC_KEY_NONE)
				&& !isValidKeyword(test) && !isSchemeSource(test) && !isHostSource(test)) {
			report.addReport(this, "Source value " + val + " could not be validated");
		}
	}

	protected boolean isHostSource(String test) {
		return AbstractCSPDirective.HOST_SOURCE.matcher(test).find();
	}

	protected boolean isSchemeSource(String test) {
		return AbstractCSPDirective.SCHEME_SOURCE.matcher(test).find();
	}

	protected boolean isValidKeyword(String val) {
		return false;
	}

	public String buildDirective() {
		StringBuilder sb = new StringBuilder();
		if (this.directiveValues.size() > 0) {
			sb.append(getDirectiveName());
			for (int i = 0; i < this.directiveValues.size(); i++) {
				sb.append(" ").append(this.directiveValues.get(i));
			}
			sb.append(buildCustomDirective());
		}
		return sb.toString();
	}

	protected String buildCustomDirective() {
		return "";
	}

	public void removeInternalDuplicates() {
		Set<String> deduped = new LinkedHashSet<String>(this.directiveValues);
		this.directiveValues.clear();
		this.directiveValues.addAll(deduped);
	}

	public void removeDuplicatesOf(AbstractCSPDirective other) {
		// TODO
	}

	public abstract void validateAndReport(CSPValidationReport report);
}
