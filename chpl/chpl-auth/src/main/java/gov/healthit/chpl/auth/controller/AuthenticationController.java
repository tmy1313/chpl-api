package gov.healthit.chpl.auth.controller;

import java.util.ArrayList;
import java.util.Arrays;

import javax.mail.MessagingException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.nulabinc.zxcvbn.Strength;

import gov.healthit.chpl.auth.EmailBuilder;
import gov.healthit.chpl.auth.Util;
import gov.healthit.chpl.auth.authentication.Authenticator;
import gov.healthit.chpl.auth.authentication.LoginCredentials;
import gov.healthit.chpl.auth.dto.UserDTO;
import gov.healthit.chpl.auth.dto.UserResetTokenDTO;
import gov.healthit.chpl.auth.json.UserResetPasswordJSONObject;
import gov.healthit.chpl.auth.jwt.JWTCreationException;
import gov.healthit.chpl.auth.manager.UserManager;
import gov.healthit.chpl.auth.user.UpdateExpiredPasswordRequest;
import gov.healthit.chpl.auth.user.UpdatePasswordRequest;
import gov.healthit.chpl.auth.user.UpdatePasswordResponse;
import gov.healthit.chpl.auth.user.UserRetrievalException;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import springfox.documentation.annotations.ApiIgnore;

/**
 * CHPL Authentication controller.
 */
@Api(value = "auth")
@RestController
@RequestMapping("/auth")
public class AuthenticationController {
    private static final Logger LOGGER = LogManager.getLogger(AuthenticationController.class);

    @Autowired
    private Authenticator authenticator;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserManager userManager;

    @Autowired private Environment env;

    /**
     * Log in a user.
     * @param credentials the user's credentials
     * @return a JWT with an authentication token
     * @throws JWTCreationException if unable to create the JWT
     * @throws UserRetrievalException if user is required to change their password
     */
    @ApiOperation(value = "Log in.",
            notes = "Call this method to authenticate a user. The value returned is that user's "
                    + "token which must be passed on all subsequent requests in the Authorization header. "
                    + "Specifically, the Authorization header must have a value of 'Bearer token-that-gets-returned'.")
    @RequestMapping(value = "/authenticate", method = RequestMethod.POST,
    consumes = MediaType.APPLICATION_JSON_VALUE,
    produces = "application/json; charset=utf-8")
    public String authenticateJSON(@RequestBody final LoginCredentials credentials) throws JWTCreationException, UserRetrievalException {

        String jwt = null;
        jwt = authenticator.getJWT(credentials);
        if (Util.getCurrentUser() != null && Util.getCurrentUser().getPasswordResetRequired()) {
            throw new UserRetrievalException("The user is required to change their password on next log in.");
        }
        String jwtJSON = "{\"token\": \"" + jwt + "\"}";

        return jwtJSON;
    }

    /**
     * Update the user's JWT to keep their session alive.
     * @return a new JWT with an extended expiration date
     * @throws JWTCreationException if unable to create the JWT
     */
    @ApiIgnore
    @RequestMapping(value = "/keep_alive", method = RequestMethod.GET,
    produces = "application/json; charset=utf-8")
    public String keepAlive() throws JWTCreationException {

        String jwt = authenticator.refreshJWT();

        String jwtJSON = "{\"token\": \"" + jwt + "\"}";

        return jwtJSON;
    }

    /**
     * Change a user's password.
     * @param request the request containing old/new passwords
     * @return a confirmation response, or an error iff the user's new password does not meet requirements
     * @throws UserRetrievalException if unable to retrieve the user
     */
    @ApiOperation(value = "Change password.",
            notes = "Change the logged in user's password as long as the old password "
                    + "passed in matches what is stored in the database.")
    @RequestMapping(value = "/change_password", method = RequestMethod.POST,
    produces = "application/json; charset=utf-8")
    public UpdatePasswordResponse changePassword(@RequestBody final UpdatePasswordRequest request)
            throws UserRetrievalException {
        UpdatePasswordResponse response = new UpdatePasswordResponse();
        if (Util.getCurrentUser() == null) {
            throw new UserRetrievalException("No user is logged in.");
        }

        // get the current user
        UserDTO currUser = userManager.getById(Util.getCurrentUser().getId());
        if (currUser == null) {
            throw new UserRetrievalException("The user with id " + Util.getCurrentUser().getId()
                    + " could not be found or the logged in user does not have permission to modify their data.");
        }

        // check the strength of the new password
        Strength strength = userManager.getPasswordStrength(currUser, request.getNewPassword());
        if (strength.getScore() < UserManager.MIN_PASSWORD_STRENGTH) {
            LOGGER.info("Strength results: [warning: {}] [suggestions: {}] [score: {}] [worst case crack time: {}]",
                    strength.getFeedback().getWarning(),
                    strength.getFeedback().getSuggestions().toString(),
                    strength.getScore(),
                    strength.getCrackTimesDisplay().getOfflineFastHashing1e10PerSecond());
            response.setStrength(strength);
            response.setPasswordUpdated(false);
            return response;
        }

        // encode the old password passed in to compare
        String currEncodedPassword = userManager.getEncodedPassword(currUser);
        boolean oldPasswordMatches = bCryptPasswordEncoder.matches(request.getOldPassword(), currEncodedPassword);
        if (!oldPasswordMatches) {
            throw new UserRetrievalException("The provided old password does not match the database.");
        } else {
            userManager.updateUserPassword(currUser.getSubjectName(), request.getNewPassword());
        }
        response.setPasswordUpdated(true);
        return response;
    }

    /**
     * Change a user's expired password.
     * @param request the request containing old/new passwords
     * @return a confirmation response, or an error iff the user's new password does not meet requirements
     * @throws UserRetrievalException if unable to retrieve the user
     * @throws JWTCreationException if cannot create a JWT
     */
    @ApiOperation(value = "Change expired password.",
            notes = "Change a user's expired password as long as the old password "
                    + "passed in matches what is stored in the database.")
    @RequestMapping(value = "/change_expired_password", method = RequestMethod.POST,
    produces = "application/json; charset=utf-8")
    public UpdatePasswordResponse changeExpiredPassword(@RequestBody final UpdateExpiredPasswordRequest request)
            throws UserRetrievalException, JWTCreationException {
        UpdatePasswordResponse response = new UpdatePasswordResponse();

        // get the user trying to change their password
        String jwt = authenticator.getJWT(request.getLoginCredentials());
        UserDTO currUser = authenticator.getUser(request.getLoginCredentials());
        if (currUser == null) {
            throw new UserRetrievalException("Cannot update password; bad username or password");
        }

        // check the strength of the new password
        Strength strength = userManager.getPasswordStrength(currUser, request.getNewPassword());
        if (strength.getScore() < UserManager.MIN_PASSWORD_STRENGTH) {
            LOGGER.info("Strength results: [warning: {}] [suggestions: {}] [score: {}] [worst case crack time: {}]",
                    strength.getFeedback().getWarning(),
                    strength.getFeedback().getSuggestions().toString(),
                    strength.getScore(),
                    strength.getCrackTimesDisplay().getOfflineFastHashing1e10PerSecond());
            response.setStrength(strength);
            response.setPasswordUpdated(false);
            return response;
        }

        // encode the old password passed in to compare
        String currEncodedPassword = userManager.getEncodedPassword(currUser);
        boolean oldPasswordMatches = bCryptPasswordEncoder.matches(request.getOldPassword(), currEncodedPassword);
        if (!oldPasswordMatches) {
            throw new UserRetrievalException("The provided old password does not match the database.");
        } else {
            userManager.updateUserPassword(currUser.getSubjectName(), request.getNewPassword());
        }
        response.setPasswordUpdated(true);
        return response;
    }

    /**
     * Allow a user to reset their password. Sends the user an email with a unique link to let them reset their password
     * @param userInfo the affected user
     * @return a JSON message indicating the email was sent
     * @throws UserRetrievalException if unable to retrieve the user
     * @throws MessagingException if unable to send the message
     */
    @ApiOperation(value = "Reset a user's password.", notes = "")
    @RequestMapping(value = "/reset_password", method = RequestMethod.POST,
    consumes = MediaType.APPLICATION_JSON_VALUE,
    produces = "application/json; charset=utf-8")
    public String resetPassword(@RequestBody final UserResetPasswordJSONObject userInfo)
            throws UserRetrievalException, MessagingException {

        UserResetTokenDTO userResetTokenDTO = userManager.createResetUserPasswordToken(
                userInfo.getUserName(), userInfo.getEmail());
        String htmlMessage = "<p>Hi, <br/>"
                + "Please follow this link to reset your password </p>"
                + "<pre>" +  env.getProperty("chplUrlBegin") + "/auth/authorize_password_reset/"
                + userResetTokenDTO.getUserResetToken() + "</pre>"
                + "<br/>"
                + "</p>"
                + "<p>Take care,<br/> "
                + "The Open Data CHPL Team</p>";
        String[] toEmails = {userInfo.getEmail()};

        EmailBuilder emailBuilder = new EmailBuilder(env);
        emailBuilder.recipients(new ArrayList<String>(Arrays.asList(toEmails)))
        .subject("Open Data CHPL Password Reset")
        .htmlMessage(htmlMessage)
        .sendEmail();

        return "{\"passwordResetEmailSent\" : true }";
    }

    /**
     * Allow the user to reset their password given they have the correct token.
     * @param token the token
     * @return the results of their reset
     */
    @ApiOperation(value = "Reset a user's password.", notes = "")
    @RequestMapping(value = "/authorize_password_reset/{token}", method = RequestMethod.POST)
    public boolean authorizePasswordReset(@PathVariable("token") final String token) {
        return userManager.authorizePasswordReset(token);
    }
}
