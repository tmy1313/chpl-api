package gov.healthit.chpl.auth.authentication;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import gov.healthit.chpl.auth.jwt.JWTAuthor;
import gov.healthit.chpl.auth.permission.GrantedPermission;
import gov.healthit.chpl.auth.user.JWTAuthenticatedUser;
import gov.healthit.chpl.auth.user.User;
import gov.healthit.chpl.domain.auth.LoginCredentials;
import gov.healthit.chpl.dto.auth.UserDTO;
import gov.healthit.chpl.exception.JWTCreationException;
import gov.healthit.chpl.exception.UserManagementException;
import gov.healthit.chpl.exception.UserRetrievalException;
import gov.healthit.chpl.manager.auth.UserManager;
import gov.healthit.chpl.util.AuthUtil;

@Service
public class UserAuthenticator implements Authenticator {
    private static final Logger LOGGER = LogManager.getLogger(UserAuthenticator.class);

    @Autowired
    private JWTAuthor jwtAuthor;

    @Autowired
    private UserManager userManager;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserDetailsChecker userDetailsChecker;

    @Override
    public UserDTO getUser(final LoginCredentials credentials)
            throws BadCredentialsException, AccountStatusException, UserRetrievalException {
        UserDTO user = getUserByName(credentials.getUserName());

        if (user != null) {
            if (user.getSignatureDate() == null) {
                throw new BadCredentialsException(
                        "Account for user " + user.getSubjectName() + " has not been confirmed.");
            }

            if (checkPassword(credentials.getPassword(), userManager.getEncodedPassword(user))) {

                try {
                    userDetailsChecker.check(user);
                    userManager.updateLastLoggedInDate(user);

                    // if login was successful reset failed logins to 0
                    if (user.getFailedLoginCount() > 0) {
                        try {
                            user.setFailedLoginCount(0);
                            updateFailedLogins(user);
                        } catch (UserManagementException ex) {
                            LOGGER.error("Error adding failed login", ex);
                        }
                    }
                } catch (AccountStatusException ex) {
                    throw ex;
                }
                return user;

            } else {
                try {
                    user.setFailedLoginCount(user.getFailedLoginCount() + 1);
                    updateFailedLogins(user);
                } catch (UserManagementException ex) {
                    LOGGER.error("Error adding failed login", ex);
                }
                throw new BadCredentialsException("Bad username and password combination.");
            }
        } else {
            throw new BadCredentialsException("There is no CHPL user with name " + credentials.getUserName());
        }
    }

    protected boolean checkPassword(final String rawPassword, final String encodedPassword) {
        return bCryptPasswordEncoder.matches(rawPassword, encodedPassword);
    }

    @Override
    public String getJWT(final UserDTO user) throws JWTCreationException {
        String jwt = null;

        Map<String, String> stringClaims = new HashMap<String, String>();
        stringClaims.put("Authority", user.getPermission().getAuthority());

        Map<String, List<String>> listClaims = new HashMap<String, List<String>>();
        List<String> identity = new ArrayList<String>();
        identity.add(user.getId().toString());
        identity.add(user.getUsername());
        identity.add(user.getFullName());
        if (user.getImpersonatedBy() != null) {
            identity.add(user.getImpersonatedBy().getId().toString());
            identity.add(user.getImpersonatedBy().getSubjectName());
        }
        listClaims.put("Identity", identity);

        jwt = jwtAuthor.createJWT(user, stringClaims, listClaims);
        return jwt;

    }

    @Override
    public String refreshJWT() throws JWTCreationException, UserRetrievalException {
        JWTAuthenticatedUser user = (JWTAuthenticatedUser) AuthUtil.getCurrentUser();

        if (user != null) {
            UserDTO userDto = getUserByName(user.getSubjectName());
            if (user.getImpersonatingUser() != null) {
                userDto.setImpersonatedBy(user.getImpersonatingUser());
            }
            return getJWT(userDto);
        } else {
            throw new JWTCreationException("Cannot generate token for Anonymous user.");
        }
    }

    @Override
    @Transactional
    public String getJWT(final LoginCredentials credentials) throws JWTCreationException {
        String jwt = null;
        UserDTO user = null;

        try {
            user = getUser(credentials);
        } catch (AccountStatusException e1) {
            throw new JWTCreationException(e1.getMessage());
        } catch (UserRetrievalException e2) {
            throw new JWTCreationException(e2.getMessage());
        }

        if (user != null) {
            jwt = getJWT(user);
        }

        return jwt;

    }

    private UserDTO getUserByName(final String userName) throws UserRetrievalException {
        Authentication authenticator = new Authentication() {
            private static final long serialVersionUID = 6718133333641942231L;

            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                List<GrantedAuthority> auths = new ArrayList<GrantedAuthority>();
                auths.add(new GrantedPermission("ROLE_USER_AUTHENTICATOR"));
                return auths;
            }

            @Override
            public Object getCredentials() {
                return null;
            }

            @Override
            public Object getDetails() {
                return null;
            }

            @Override
            public Object getPrincipal() {
                return null;
            }

            @Override
            public boolean isAuthenticated() {
                return true;
            }

            @Override
            public void setAuthenticated(final boolean arg0) throws IllegalArgumentException {
            }

            @Override
            public String getName() {
                return "AUTHENTICATOR";
            }

        };

        SecurityContextHolder.getContext().setAuthentication(authenticator);
        try {
            UserDTO user = userManager.getByName(userName);
            return user;
        } finally {
            SecurityContextHolder.getContext().setAuthentication(null);
        }

    }

    private void updateFailedLogins(final UserDTO userToUpdate) throws UserRetrievalException, UserManagementException {
        Authentication authenticator = new Authentication() {

            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                List<GrantedAuthority> auths = new ArrayList<GrantedAuthority>();
                auths.add(new GrantedPermission("ROLE_USER_AUTHENTICATOR"));
                return auths;
            }

            @Override
            public Object getCredentials() {
                return null;
            }

            @Override
            public Object getDetails() {
                return null;
            }

            @Override
            public Object getPrincipal() {
                return null;
            }

            @Override
            public boolean isAuthenticated() {
                return true;
            }

            @Override
            public void setAuthenticated(final boolean arg0) throws IllegalArgumentException {
            }

            @Override
            public String getName() {
                return "AUTHENTICATOR";
            }

        };

        SecurityContextHolder.getContext().setAuthentication(authenticator);
        try {
            userManager.updateFailedLoginCount(userToUpdate);
        } catch (Exception ex) {
            throw new UserManagementException(
                    "Error increasing the failed login count for user " + userToUpdate.getSubjectName(), ex);
        } finally {
            SecurityContextHolder.getContext().setAuthentication(null);
        }
    }

    public JWTAuthor getJwtAuthor() {
        return jwtAuthor;
    }

    public void setJwtAuthor(final JWTAuthor jwtAuthor) {
        this.jwtAuthor = jwtAuthor;
    }

    @Override
    @PreAuthorize("@permissions.hasAccess(T(gov.healthit.chpl.permissions.Permissions).USER_PERMISSIONS, "
            + "T(gov.healthit.chpl.permissions.domains.SecuredUserDomainPermissions).IMPERSONATE_USER, #username)")
    public String impersonateUser(final String username)
            throws UserRetrievalException, JWTCreationException, UserManagementException {
        JWTAuthenticatedUser user = (JWTAuthenticatedUser) AuthUtil.getCurrentUser();
        if (user.getImpersonatingUser() != null) {
            throw new UserManagementException("Unable to impersonate user while already impersonating");
        }
        UserDTO impersonatingUser = getUserByName(user.getSubjectName());
        UserDTO impersonatedUser = getUserByName(username);

        impersonatedUser.setImpersonatedBy(impersonatingUser);
        return getJWT(impersonatedUser);
    }

    @Override
    public String unimpersonateUser(final User user) throws JWTCreationException, UserRetrievalException {
        return getJWT(getUserByName(user.getSubjectName()));
    }
}
