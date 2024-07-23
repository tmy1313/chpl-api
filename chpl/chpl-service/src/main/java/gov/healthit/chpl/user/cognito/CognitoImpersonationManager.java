package gov.healthit.chpl.user.cognito;

import java.util.LinkedHashMap;
import java.util.Map;

import gov.healthit.chpl.CognitoSecretHash;
import gov.healthit.chpl.auth.authentication.JWTUserConverterFacade;
import gov.healthit.chpl.auth.user.JWTAuthenticatedUser;
import gov.healthit.chpl.domain.auth.User;
import gov.healthit.chpl.exception.UserRetrievalException;
import gov.healthit.chpl.util.AuthUtil;
import lombok.extern.log4j.Log4j2;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminRespondToAuthChallengeRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminRespondToAuthChallengeResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthenticationResultType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ChallengeNameType;

@Log4j2
public class CognitoImpersonationManager {

    private CognitoApiConfiguration config;
    private CognitoApiWrapper cognitoApiWrapper;
    private JWTUserConverterFacade jwtUserConverterFacade;

    public CognitoImpersonationManager(CognitoApiConfiguration config, CognitoApiWrapper cognitoApiWrapper, JWTUserConverterFacade jwtUserConverterFacade) {
        this.config = config;
        this.cognitoApiWrapper = cognitoApiWrapper;
        this.jwtUserConverterFacade = jwtUserConverterFacade;
    }

    public CognitoAuthenticationResponse impersonate(String email) throws CognitoAuthenticationChallengeException {
        String secretHash = CognitoSecretHash.calculateSecretHash(
                config.getClientId(),
                config.getUserPoolClientSecret(),
                email);

        Map<String, String> authParams = new LinkedHashMap<String, String>();
        authParams.put("USERNAME", email);
        authParams.put("SECRET_HASH", secretHash);

        AdminInitiateAuthRequest authRequest = AdminInitiateAuthRequest.builder()
                .authFlow(AuthFlowType.CUSTOM_AUTH)
                .userPoolId(config.getUserPoolId())
                .clientId(config.getClientId())
                .authParameters(authParams)
                .build();

        try {
            AdminInitiateAuthResponse authResult = config.getCognitoClient().adminInitiateAuth(authRequest);
            if (authResult.challengeName() != null
                    && authResult.challengeName().equals(ChallengeNameType.CUSTOM_CHALLENGE)) {

                AuthenticationResultType challengeResult = respondToImpersonationChallenge(email, authResult.session());

                return CognitoAuthenticationResponse.builder()
                        .accessToken(challengeResult.accessToken())
                        .idToken(challengeResult.idToken())
                        .refreshToken(challengeResult.refreshToken())
                        .user(getUser(challengeResult.idToken()))
                        .build();
            }
            return  null;
        } catch (Exception e) {
            //This is cluttering the logs when the SSO flag is on, and the user logs in using CHPL creds
            //We might want to uncomment it when we move to only using Cognito creds
            LOGGER.error("Authentication error: {}", e.getMessage(), e);
            return null;
        }
    }

    private AuthenticationResultType respondToImpersonationChallenge(String email, String sessionId) {
        AdminRespondToAuthChallengeRequest request = AdminRespondToAuthChallengeRequest.builder()
                .userPoolId(config.getUserPoolId())
                .clientId(config.getClientId())
                .challengeName("CUSTOM_CHALLENGE")
                .clientMetadata(Map.of("IMPERSONATED_BY", AuthUtil.getCurrentUser().getEmail()))
                .challengeResponses(Map.of("USERNAME", "at-onc-cognito@test.com",
                        "ANSWER", "IMPERSONATING",  // This key is required Cognito, but not is not used
                        "SECRET_HASH", config.calculateSecretHash(email)))
                .session(sessionId)
                .build();

        try {
            AdminRespondToAuthChallengeResponse response = config.getCognitoClient().adminRespondToAuthChallenge(request);

            if (response.challengeName() != null) {
                LOGGER.error("Received Challenge {} when responding to IMPERSONATE_CHALLENGE");
                return null;
            }
            return response.authenticationResult();
        } catch (Exception e) {
            LOGGER.error("Error responding to IMPERSONATE_CHALLENGE challenge: {}", e.getMessage(), e);
            return null;
        }
    }

    private User getUser(String idToken) {
        JWTAuthenticatedUser jwtUser = jwtUserConverterFacade.getAuthenticatedUser(idToken);
        try {
            return cognitoApiWrapper.getUserInfo(jwtUser.getCognitoId());
        } catch (UserRetrievalException e) {
            LOGGER.error("Could not decode JWT Token");
            return null;
        }
    }
}
