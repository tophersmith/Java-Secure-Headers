# Java-Secure-Headers
#### Author: Chris Smith, 2015

## Code Status
[![Build Status](https://travis-ci.org/tophersmith/Java-Secure-Headers.svg?branch=master)](https://travis-ci.org/tophersmith/Java-Secure-Headers)

## Docs
[Java-Secure-Headers Documentation](http://tophersmith.github.io/Java-Secure-Headers/javadoc/)

## Goal
Provide a set of easy-to-configure security headers that allow dynamic web applications to build validated and properly formatted security headers procedurally.

## Installation
### Standalone
JDK7: [secure-headers-jdk7.jar](https://tophersmith.github.io/Java-Secure-Headers/jar/secure-headers-jdk7.jar)

JDK8: [secure-headers-jdk8.jar](https://tophersmith.github.io/Java-Secure-Headers/jar/secure-headers-jdk8.jar)

### Maven
``` xml
<dependency>
  <groupId>TBD</groupId>
  <artifactId>TBD</artifactId>
</dependency>
```

## Design
### Supported Headers     

Header                    | Official Documentation     | Description
------------------------- | -------------------------- | --------------
Content-Security-Policy   | [CSP Level 2](http://www.w3.org/TR/CSP2/) | The Content-Security-Policy header is used in response headers to inform the User-Agent from where certain kinds of resources may be loaded. This defends against XSS, UI Redress, and many other kinds of attacks.
Strict-Transport-Security | [RFC-6797](https://tools.ietf.org/html/rfc6797) | The Strict-Transport-Security header is used in response headers inform the browser User-Agent that this site must be communicated with using HTTPS. This defends against Man in the Middle attacks
X-Content-Type-Options    | [MSDN](https://blogs.msdn.microsoft.com/ie/2008/09/02/ie8-security-part-vi-beta-2-update/) + [Chrome Extensions](https://developer.chrome.com/extensions/hosting) | The X-Content-Type-Options header is used in response headers to protect against the User Agent trying to guess at the content type of the response. This defends against MIME confusion and Content Type Sniffing attacks. 
X-Frame-Options           | [RFC-7034](https://tools.ietf.org/html/rfc7034) | The X-Frame-Options header is used in response headers to configure which sites may frame this response's resource. This defends against UI Redress attacks such as Clickjacking
X-XSS-Protection          | [MSDN](https://blogs.msdn.microsoft.com/ie/2008/07/02/ie8-security-part-iv-the-xss-filter/) | The X-XSS-Protection header is used in response headers to require browser User Agents to enable reflective XSS protection. This defends the application against some XSS attacks.

### Architectural Decisions

In general, the primary Architectural Pattern used in this project is the [Builder Pattern](https://en.wikipedia.org/wiki/Builder_pattern) where the builders accept different kinds of input to build up the complete header value before outputting via a build() call.

The class SecurityHeaders provides the overall data structure to hold all other AbstractHeader instances. Each concrete class implementing AbstractHeader (as described in [Supported Headers](#Supported-Headers) above) is designed - again as a Builder - to construct the proper values for the class's header definition. All implementers of AbstractHeader must implement a validate() method. The validate() method is called on each Header attached to a SecurityHeaders via the validateAllHeaders() call, though both are not required to be called in order to construct the header values. The buildHeaderValue() in each Header, does the actual construction of the value, usually called via the buildHeaders() or buildHeaderLines() methods in SecurityHeaders.

Finally, the ContentSecurityPolicy contains one further builder pattern in the AbstractCSPDirective implementations. Again, each directive must implement the validateAndReport(CSPValidationReport report) which is optional to call. The validation report generated can be used to report validation warnings and errors back to the creator (such as a web application admin). Generally, directives only allow a user to set or add directive values that make sense for the directive. However, all directives additionally implement an addExperimentalValue(String value) which are not validated. This is to support the agility of the CSP documentation. Since CSP generation can be somewhat difficult, particularly when generated dynamically, this library also implements a reduce() function which is called automatically during header building if set via setReduce(true). Reduction tests the value for duplicate values, removing them and then removes any definitions that are blank. 

All relevant library data should be exposed in such a way as to allow for further development via class extension or implementation

### Example Usage
[Examples](./EXAMPLES.md)

## Tests
Included is a test suite SecurityHeadersSuite which executes sets of JUnit tests that cover over 97% of instructions in the library (some instructions are missed in defensive code branches).

## License
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0.txt)
