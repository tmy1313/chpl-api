package gov.healthit.chpl.permissions.domains.secureduser;

import org.springframework.stereotype.Component;

import gov.healthit.chpl.dto.auth.UserDTO;
import gov.healthit.chpl.permissions.domains.ActionPermissions;

@Component("securedUserUpdateActionPermissions")
public class UpdateActionPermissions extends ActionPermissions {

    @Override
    public boolean hasAccess() {
        return false;

    }

    @Override
    public boolean hasAccess(final Object obj) {
        if (!(obj instanceof UserDTO)) {
            return false;
        }
        UserDTO user = (UserDTO) obj;
        return getResourcePermissions().hasPermissionOnUser(user);
    }

}
