//  Copyright 2022 Michael Deller
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

import Foundation
import AppAuth

class Authorization: ObservableObject {
    
    private var userAgentSession: OIDExternalUserAgentSession?
    
    let clientId: String = "13f360f4-81c6-405a-bb45-3173471274c8"
    let issuer: String = "https://auth.pingone.com/92ab6bdf-7c0c-4c16-b73d-c379556e6eee/as"
    let redirectUrl = URL(string: "com.example://calback")!

    func discovery() {
    
        Logger.debug(message: "discovery func")
        
        let issuerUrl = URL(string: issuer)!
        
        Logger.debug(message: "discovery for issuer: \(issuerUrl)")
        
        OIDAuthorizationService.discoverConfiguration(forIssuer: issuerUrl) { configuration, error in
            guard let config = configuration else {
                print("Error retrieving discovery document: \(error?.localizedDescription ?? "Unknown error")")
                return
            }
            // Logger.debug(message: OIDServiceDiscovery.tokenEndpoint)
            Logger.debug(message: "authorizationEndpoint: \(config.authorizationEndpoint)")

            self.authRequest(configuration: config)
            
        }
        
    }
    
    func authRequest(configuration: OIDServiceConfiguration) {
        
        Logger.debug(message: "authenticate func")
              
        let viewController: UIViewController = UIApplication.shared.windows.first!.rootViewController!
                
        let request = OIDAuthorizationRequest(configuration: configuration,
                                              clientId: clientId,
                                              clientSecret: nil,
                                              scopes: [OIDScopeOpenID, OIDScopeProfile],
                                              redirectURL: redirectUrl,
                                              responseType: OIDResponseTypeCode,
                                              additionalParameters: nil)

        Logger.debug(message: "Initiating authorization request with scope: \(request.scope ?? "DEFAULT_SCOPE")")
        
        let userAgent = OIDExternalUserAgentIOS(presenting: viewController)
        
        self.userAgentSession = OIDAuthorizationService.present(request, externalUserAgent: userAgent!) { response, ex in
                    
            if response != nil {

                let code = response!.authorizationCode == nil ? "" : response!.authorizationCode!
                let state = response!.state == nil ? "" : response!.state!
                Logger.debug(message: "Authorization Code: \(code)")
                Logger.debug(message: "State: \(state)")

                self.codeExchange(authResponse: response!)
                
            }
        }
    }
    
    func codeExchange(authResponse: OIDAuthorizationResponse) {
        
        Logger.debug(message: "codeExchange func")
        
        let extraParams = [String: String]()
        let request = authResponse.tokenExchangeRequest(withAdditionalParameters: extraParams)
        
        OIDAuthorizationService.perform(
            request!,
            originalAuthorizationResponse: authResponse) { tokenResponse, ex in

            if tokenResponse != nil {
                
                let accessToken = tokenResponse!.accessToken == nil ? "" : tokenResponse!.accessToken!
                let refreshToken = tokenResponse!.refreshToken == nil ? "" : tokenResponse!.refreshToken!
                let idToken = tokenResponse!.idToken == nil ? "" : tokenResponse!.idToken!
                Logger.debug(message: "AT: \(accessToken), RT: \(refreshToken), IDT: \(idToken)" )
                
            } else {
                
                Logger.error(message: "Unable to exchange authorization code for access token")
                
            }
        }
    }
}
