# Examples
## Creating Headers
This case is very general just to show some common operations.
```java

private List<Entry<String, String>> makeSecurityHeaders(){
	SecurityHeaders head = new SecurityHeaders();

	//X-FRAME-OPTIONS set to deny framing
	XFrameOptionsHeader xframe = new XFrameOptionsHeader().setDeny();

	//X-XSS-Protection enabled and set to block
	XXSSProtectionHeader xss = new XXSSProtectionHeader().enableBlock().enableProtection();

	//CSP built with a default-src and script-src
	ContentSecurityPolicyHeader csp = new ContentSecurityPolicyHeader(CSPHeaderName.CSP);
	ContentSecurityPolicy policy = new ContentSecurityPolicy();
	policy.addDirective(new DefaultSrcDirective().addSelf().addSource("http://foobar.com"));
	policy.addDirective(new ScriptSrcDirective().addSelf().addUnsafeInline());
	csp.setPolicy(policy);

	//add all headers
	head.addHeader(xframe).addHeader(xss).addHeader(csp);

	//(Optional) validate the headers
	List<String> issues = head.validateAllHeaders();

	//output to stderr
	if(issues != null){
		for(String issue : issues){
			System.err.println(issue);
		}
	}

	//output to console
	List<Entry<String, String>> headers = head.buildHeaders();
	for(Entry<String, String> entry : headers){
		System.out.println(entry.getKey() + ": " + entry.getValue());
	}

	//alternate output to console
	List<String> headerLines = head.buildHeaderLines();
	for(String line : headerLines){
		System.out.println(line);
	}

	/**
	 * Output in console for the above code:
	 * X-Frame-Options: DENY
	 * X-XSS-Protection: 1; mode=block
	 * Content-Security-Policy: script-src 'self' 'unsafe-inline'; default-src 'self' http://foobar.com
	 * X-Frame-Options: DENY
	 * X-XSS-Protection: 1; mode=block
	 * Content-Security-Policy: script-src 'self' 'unsafe-inline'; default-src 'self' http://foobar.com
	 */
}

public void addHeadersToResponse(HttpServletResponse response){
	List<Entry<String, String>> headers = makeSecurityHeaders();
	for(Entry<String, String> entry : headers){
		response.setHeader(entry.getKey(), entry.getValue());
	}
}

```

## Content-Security-Policy 
The Content Security Policy is a very difficult header to generate successfully. This example shows how 
to generate, validate, and build the policy.
```java

ContentSecurityPolicy policy = new ContentSecurityPolicy(PolicyLevel.CSP1);

DefaultSrcDirective defSrc = new DefaultSrcDirective();
defSrc.addSelf();
policy.addDirective(defSrc);

ConnectSrcDirective conSrc = new ConnectSrcDirective();
conSrc.addSelf();
conSrc.addSource("*");
policy.addDirective(defSrc);

ImgSrcDirective imgSrc = new ImgSrcDirective();
imgSrc.addSelf();	
imgSrc.addSource("https://*.company.com");
policy.addDirective(defSrc);

ScriptSrcDirective scpSrc = new ScriptSrcDirective();
scpSrc.addSelf();
scpSrc.addSource("http:");
scpSrc.addUnsafeEval();
scpSrc.addUnsafeInline();
policy.addDirective(defSrc);

PluginTypesDirective plugin = new PluginTypesDirective();
plugin.addMediaType("application/media");
policy.addDirective(defSrc);

//check for validation errors
if(!policy.isValid()){
	List<String> reports = policy.getValidationErrorReports();
	for(String report : reports){
		System.err.println(report);
	}
} else{
	System.out.println(policy.build());
}
	
```

## CSP nonces
As nonces and hashes have a need to change from response to response, the ScriptSrcDirective and 
StyleSrcDirective can reset each, allowing the directive to be re-used without needing to rebuild 
the directive or policy.
```java

<%
	//This is application-specific. CSP Should be cached somehow.
	ContentSecurityPolicy policy = Session.retrieveCSP(); 
	ScriptSrcDirective scriptSrc = (ScriptSrcDirective)policy.getDirective(ScriptSrcDirective.NAME);
	scriptSrc.resetNonces();
	
	//generate a nonce of 12 characters
	String nonce = ScriptSrcDirective.generateNonce(12); 
	scriptSrc.addNonce(nonce);
%>

<script nonce="<%=nonce %>">
	...
</script>
	
```