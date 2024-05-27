// Burp Suite Extension Name: Sharpener
// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)
// Released initially as open source by MDSec - https://www.mdsec.co.uk
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener

package ninja.burpsuite.extension.sharpener.capabilities.implementations;

import java.util.Arrays;

import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.proxy.http.*;
import ninja.burpsuite.extension.sharpener.ExtensionSharedParameters;
import ninja.burpsuite.extension.sharpener.capabilities.objects.CapabilitySettings;

public class PwnFoxProxyRequestResponseHandler implements ProxyRequestHandler, ProxyResponseHandler {
    ExtensionSharedParameters sharedParameters;
    CapabilitySettings capabilitySettings;

    public PwnFoxProxyRequestResponseHandler(ExtensionSharedParameters sharedParameters,
            CapabilitySettings capabilitySettings) {
        this.sharedParameters = sharedParameters;
        this.capabilitySettings = capabilitySettings;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        var headerList = interceptedRequest.headers();
        if (headerList != null) {
            if (capabilitySettings.isEnabled()) {
                for (var item : headerList) {
                    if (item.name().equalsIgnoreCase("x-pwnfox-color")) {
                        var pwnFoxColor = item.value();
                        if (!pwnFoxColor.isEmpty()) {
                            interceptedRequest.annotations()
                                    .setHighlightColor(HighlightColor.highlightColor(pwnFoxColor));
                        }
                        return ProxyRequestReceivedAction
                                .continueWith(interceptedRequest.withRemovedHeader("X-PwnFox-Color"));
                    }
                }
            }
        }
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {

        var OPTIONS_VERB = "OPTIONS";

        var ACRH = "Access-Control-Request-Headers";

        var ACAH = "Access-Control-Allow-Headers";

        var PWNFOX_HEADER = "X-Pwnfox-Color";

        var PWNFOX_HEADER_LOWER = PWNFOX_HEADER.toLowerCase();

        var initiatingRequest = interceptedResponse.initiatingRequest();

        var initiatingRequestMethod = initiatingRequest.method();

        if (initiatingRequestMethod.equals(OPTIONS_VERB)) {

            var corsRequestHeadersString = initiatingRequest.headerValue(ACRH);

            if (null != corsRequestHeadersString) {

                if (capabilitySettings.isEnabled()) {

                    corsRequestHeadersString = corsRequestHeadersString.toLowerCase();

                    var corsRequestHeadersArray = corsRequestHeadersString.split(",\\s*");

                    var corsRequestHeadersList = Arrays.asList(corsRequestHeadersArray);

                    if (corsRequestHeadersList.contains(PWNFOX_HEADER_LOWER)) {

                        var updatedCorsResponseHeadersString = PWNFOX_HEADER;

                        var corsResponseHeadersString = interceptedResponse.headerValue(ACAH);

                        if (null != corsResponseHeadersString) {

                            var corsResponseHeadersArray = corsResponseHeadersString.toLowerCase().split(",\\s*");

                            var corsResponseHeadersList = Arrays.asList(corsResponseHeadersArray);

                            if (!corsResponseHeadersList.contains(PWNFOX_HEADER_LOWER)) {

                                updatedCorsResponseHeadersString += ", " + corsResponseHeadersString;

                                return ProxyResponseReceivedAction.continueWith(interceptedResponse
                                        .withUpdatedHeader(ACAH, updatedCorsResponseHeadersString));
                            }

                        } else {

                            return ProxyResponseReceivedAction.continueWith(interceptedResponse
                                    .withAddedHeader(ACAH, updatedCorsResponseHeadersString));
                        }
                    }
                }
            }
        }

        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
}