package gov.healthit.chpl.dao.search;

import java.util.Date;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;
import org.springframework.test.context.support.DirtiesContextTestExecutionListener;
import org.springframework.test.context.transaction.TransactionalTestExecutionListener;
import org.springframework.transaction.annotation.Transactional;

import com.github.springtestdbunit.DbUnitTestExecutionListener;
import com.github.springtestdbunit.annotation.DatabaseSetup;

import gov.healthit.chpl.auth.permission.GrantedPermission;
import gov.healthit.chpl.auth.user.JWTAuthenticatedUser;
import gov.healthit.chpl.caching.UnitTestRules;
import gov.healthit.chpl.dao.EntityRetrievalException;
import gov.healthit.chpl.dao.ProductVersionDAO;
import gov.healthit.chpl.domain.search.CertifiedProductBasicSearchResult;
import gov.healthit.chpl.dto.ProductVersionDTO;
import junit.framework.TestCase;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = { gov.healthit.chpl.CHPLTestConfig.class })
@TestExecutionListeners({ DependencyInjectionTestExecutionListener.class,
    DirtiesContextTestExecutionListener.class,
    TransactionalTestExecutionListener.class,
    DbUnitTestExecutionListener.class })
@DatabaseSetup("classpath:data/testData.xml")
public class CertifiedProductBasicSearchDAOTest extends TestCase {

	@Autowired
	private CertifiedProductSearchDAO cpSearchDao;
	
	@Rule
    @Autowired
    public UnitTestRules cacheInvalidationRule;

	@BeforeClass
	public static void setUpClass() throws Exception {
	}

	@Test
	@Transactional(readOnly = true)
	public void getAllCertifiedProducts() {
		Date startDate = new Date();
		List<CertifiedProductBasicSearchResult> results = cpSearchDao.getAllCertifiedProducts();
		Date endDate = new Date();
		System.out.println("Search took " + ((endDate.getTime() - startDate.getTime())/1000) + " seconds");
		
		assertNotNull(results);
		assertEquals(16, results.size());
		
		boolean checkedCriteria = false;
		boolean checkedCqms = false;
		for(CertifiedProductBasicSearchResult result : results) {
			if(result.getId().longValue() == 1L) {
				checkedCriteria = true;
				assertNotNull(result.getCriteriaMet().size());
				assertEquals(4, result.getCriteriaMet().size());
			}
			if(result.getId().longValue() == 2L) {
				checkedCqms = true;
				assertNotNull(result.getCqmsMet().size());
				assertEquals(2, result.getCqmsMet().size());
			}
		}
		assertTrue(checkedCriteria);
		assertTrue(checkedCqms);
	}
}