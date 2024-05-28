// Burp Suite Extension Name: Sharpener
// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)
// Released initially as open source by MDSec - https://www.mdsec.co.uk
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener

package ninja.burpsuite.extension.sharpener.capabilities.implementations;

import java.util.ArrayList;
import java.util.Arrays;

import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.*;
import ninja.burpsuite.extension.sharpener.ExtensionSharedParameters;
import ninja.burpsuite.extension.sharpener.capabilities.objects.CapabilitySettings;

public class PwnFoxProxyRequestResponseHandler implements ProxyRequestHandler, ProxyResponseHandler {

    String PWNFOX_HEADER = "X-Pwnfox-Color";

    String CONTENT_TYPE_HEADER = "Content-Type";

    ExtensionSharedParameters sharedParameters;

    CapabilitySettings capabilitySettings;

    public PwnFoxProxyRequestResponseHandler(ExtensionSharedParameters sharedParameters,
            CapabilitySettings capabilitySettings) {
        this.sharedParameters = sharedParameters;
        this.capabilitySettings = capabilitySettings;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {

        var OPTIONS_VERB = "OPTIONS";

        var ACRH = "Access-Control-Request-Headers";

        HttpRequest modifiedRequest = interceptedRequest;

        if (capabilitySettings.isEnabled()) {

            var annotations = interceptedRequest.annotations();

            var pwnFoxHeaderValue = modifiedRequest.headerValue(PWNFOX_HEADER);

            if (null != pwnFoxHeaderValue) {

                modifiedRequest = modifiedRequest.withRemovedHeader(PWNFOX_HEADER);

                var pwnFoxColour = HighlightColor.highlightColor(pwnFoxHeaderValue);

                annotations.setHighlightColor(pwnFoxColour);
            }

            var requestMethod = modifiedRequest.method();

            if (requestMethod.equals(OPTIONS_VERB)) {

                var corsRequestHeadersString = modifiedRequest.headerValue(ACRH);

                if (null != corsRequestHeadersString) {

                    var corsRequestHeadersArray = corsRequestHeadersString.split(",\\s*");

                    var modifiedCorsRequestHeadersList = new ArrayList<String>();

                    var isPwnFoxPreflight = false;

                    for (var i = 0; i < corsRequestHeadersArray.length; i++) {

                        var corsRequestHeader = corsRequestHeadersArray[i];

                        if (corsRequestHeader.equalsIgnoreCase(PWNFOX_HEADER)) {

                            isPwnFoxPreflight = true;

                        } else {

                            modifiedCorsRequestHeadersList.add(corsRequestHeader);
                        }
                    }

                    if (isPwnFoxPreflight) {

                        var notes = annotations.notes();

                        notes += "\n" + PWNFOX_HEADER + "\n";

                        if (0 == modifiedCorsRequestHeadersList.size()) {

                            modifiedCorsRequestHeadersList.add(CONTENT_TYPE_HEADER);

                            notes += CONTENT_TYPE_HEADER + "\n";
                        }

                        annotations.setNotes(notes);

                        var modifiedCorsRequestHeadersString = String.join(", ", modifiedCorsRequestHeadersList);

                        modifiedRequest = modifiedRequest.withUpdatedHeader(ACRH, modifiedCorsRequestHeadersString);
                    }
                }
            }
        }

        return ProxyRequestReceivedAction.continueWith(modifiedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {

        var ORIGIN_HEADER = "Origin";

        var ACRM = "Access-Control-Request-Method";

        var LOCATION_HEADER = "Location";

        var SET_COOKIE_HEADER = "Set-Cookie";

        var ACAO = "Access-Control-Allow-Origin";

        var ACAC = "Access-Control-Allow-Credentials";

        var ACAH = "Access-Control-Allow-Headers";

        var ACAM = "Access-Control-Allow-Methods";

        HttpResponse modifiedResponse = interceptedResponse;

        if (capabilitySettings.isEnabled()) {

            var annotations = interceptedResponse.annotations();

            var notes = annotations.notes();

            if (notes.contains(PWNFOX_HEADER)) {

                var modifiedCorsResponseHeadersString = PWNFOX_HEADER;

                var corsResponseHeadersString = modifiedResponse.headerValue(ACAH);

                modifiedResponse = modifiedResponse.withRemovedHeader(ACAH);

                if (null != corsResponseHeadersString) {

                    modifiedCorsResponseHeadersString += ", " + corsResponseHeadersString;

                }

                if (notes.contains(CONTENT_TYPE_HEADER)) {

                    modifiedResponse = modifiedResponse.withStatusCode((short) 200);

                    modifiedResponse = modifiedResponse.withRemovedHeader(LOCATION_HEADER);

                    modifiedResponse = modifiedResponse.withRemovedHeader(SET_COOKIE_HEADER);

                    modifiedResponse = modifiedResponse.withBody("");

                    var initiatingRequest = interceptedResponse.initiatingRequest();

                    var origin = initiatingRequest.headerValue(ORIGIN_HEADER);

                    if (null != origin) {

                        modifiedResponse = modifiedResponse.withRemovedHeader(ACAO);

                        modifiedResponse = modifiedResponse.withAddedHeader(ACAO, origin);

                        modifiedResponse = modifiedResponse.withRemovedHeader(ACAC);

                        modifiedResponse = modifiedResponse.withAddedHeader(ACAC, "true");

                        var corsRequestMethodString = initiatingRequest.headerValue(ACRM);

                        if (null != corsRequestMethodString) {

                            var modifiedCorsResponseMethodsString = corsRequestMethodString;

                            var corsResponseMethodsString = modifiedResponse.headerValue(ACAM);

                            modifiedResponse = modifiedResponse.withRemovedHeader(ACAM);

                            if (null != corsResponseMethodsString && !corsResponseMethodsString.equals("*")) {

                                var corsResponseMethodsArray = corsResponseMethodsString.split(",\\s*");

                                var corsResponseMethodsList = Arrays.asList(corsResponseMethodsArray);

                                if (!corsResponseMethodsList.contains(corsRequestMethodString)) {

                                    modifiedCorsResponseMethodsString += ", " + corsResponseMethodsString;

                                } else {

                                    modifiedCorsResponseMethodsString = corsResponseMethodsString;
                                }
                            }

                            modifiedResponse = modifiedResponse.withAddedHeader(ACAM,
                                    modifiedCorsResponseMethodsString);
                        }
                    }
                }

                modifiedResponse = modifiedResponse.withAddedHeader(ACAH, modifiedCorsResponseHeadersString);
            }
        }

        return ProxyResponseReceivedAction.continueWith(modifiedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
}