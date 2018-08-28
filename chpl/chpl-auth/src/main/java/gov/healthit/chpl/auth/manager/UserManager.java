package gov.healthit.chpl.auth.manager;

import java.util.List;
import java.util.Set;

import gov.healthit.chpl.auth.dto.UserDTO;
import gov.healthit.chpl.auth.dto.UserPermissionDTO;
import gov.healthit.chpl.auth.json.User;
import gov.healthit.chpl.auth.json.UserCreationJSONObject;
import gov.healthit.chpl.auth.json.UserInfoJSONObject;
import gov.healthit.chpl.auth.permission.UserPermissionRetrievalException;
import gov.healthit.chpl.auth.user.UserCreationException;
import gov.healthit.chpl.auth.user.UserManagementException;
import gov.healthit.chpl.auth.user.UserRetrievalException;

public interface UserManager {

    UserDTO create(UserCreationJSONObject userInfo) throws UserCreationException, UserRetrievalException;

    UserDTO update(User userInfo) throws UserRetrievalException;

    UserDTO update(UserDTO user) throws UserRetrievalException ;

    void delete(UserDTO user) throws UserRetrievalException, UserPermissionRetrievalException, UserManagementException;

    void delete(String userName) throws UserRetrievalException, UserPermissionRetrievalException, UserManagementException ;

    List<UserDTO> getAll();

    List<UserDTO> getUsersWithPermission(String permissionName);

    UserDTO getById(Long id) throws UserRetrievalException;

    UserDTO getByName(String userName) throws UserRetrievalException;

    UserInfoJSONObject getUserInfo(String userName) throws UserRetrievalException;

    void grantRole(String userName, String role) throws UserRetrievalException, UserManagementException, UserPermissionRetrievalException;

    void grantAdmin(String userName) throws UserRetrievalException, UserPermissionRetrievalException, UserManagementException;

    void removeRole(UserDTO user, String role) throws UserRetrievalException, UserPermissionRetrievalException, UserManagementException;

    void removeRole(String userName, String role) throws UserRetrievalException, UserPermissionRetrievalException, UserManagementException;

    void removeAdmin(String userName) throws UserPermissionRetrievalException, UserRetrievalException, UserManagementException;

    void updateFailedLoginCount(UserDTO userToUpdate) throws UserRetrievalException;

    void updateUserPassword(String userName, String password) throws UserRetrievalException;

    String resetUserPassword(String username, String email) throws UserRetrievalException;

    String getEncodedPassword(UserDTO user) throws UserRetrievalException;

    String encodePassword(String password);

    Set<UserPermissionDTO> getGrantedPermissionsForUser(UserDTO user);
}
