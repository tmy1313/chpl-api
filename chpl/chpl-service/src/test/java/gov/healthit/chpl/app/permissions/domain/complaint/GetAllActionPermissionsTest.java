package gov.healthit.chpl.app.permissions.domain.complaint;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import gov.healthit.chpl.app.permissions.domain.ActionPermissionsBaseTest;
import gov.healthit.chpl.domain.CertificationBody;
import gov.healthit.chpl.domain.complaint.Complaint;
import gov.healthit.chpl.permissions.ResourcePermissions;
import gov.healthit.chpl.permissions.domains.complaint.GetAllActionPermissions;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {
        gov.healthit.chpl.CHPLTestConfig.class
})
public class GetAllActionPermissionsTest extends ActionPermissionsBaseTest {

    @Mock
    private ResourcePermissions resourcePermissions;

    @InjectMocks
    private GetAllActionPermissions permissions;

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);

        Mockito.when(resourcePermissions.getAllAcbsForCurrentUser()).thenReturn(getAllAcbForUser(2l, 4l));
    }

    @Override
    @Test
    public void hasAccess_Admin() throws Exception {
        setupForAdminUser(resourcePermissions);
        assertTrue(permissions.hasAccess());

        Complaint complaint = new Complaint();
        assertTrue(permissions.hasAccess(complaint));
    }

    @Override
    @Test
    public void hasAccess_Onc() throws Exception {
        setupForOncUser(resourcePermissions);
        assertTrue(permissions.hasAccess());

        Complaint complaint = new Complaint();
        assertTrue(permissions.hasAccess(complaint));
    }

    @Override
    @Test
    public void hasAccess_Acb() throws Exception {
        setupForAcbUser(resourcePermissions);
        assertTrue(permissions.hasAccess());

        Complaint complaint = new Complaint();
        complaint.setCertificationBody(new CertificationBody());
        complaint.getCertificationBody().setId(2l);
        assertTrue(permissions.hasAccess(complaint));

        complaint.getCertificationBody().setId(1l);
        assertFalse(permissions.hasAccess(complaint));
    }

    @Override
    @Test
    public void hasAccess_Atl() throws Exception {
        setupForAtlUser(resourcePermissions);
        assertFalse(permissions.hasAccess());

        Complaint complaint = new Complaint();
        assertFalse(permissions.hasAccess(complaint));
    }

    @Override
    @Test
    public void hasAccess_Cms() throws Exception {
        setupForCmsUser(resourcePermissions);
        assertFalse(permissions.hasAccess());

        Complaint complaint = new Complaint();
        assertFalse(permissions.hasAccess(complaint));
    }

    @Override
    @Test
    public void hasAccess_Anon() throws Exception {
        setupForAnonUser(resourcePermissions);
        assertFalse(permissions.hasAccess());

        Complaint complaint = new Complaint();
        assertFalse(permissions.hasAccess(complaint));
    }

}
