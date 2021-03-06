package gov.healthit.chpl.validation.cmsid;

import java.util.ArrayList;
import java.util.List;

import gov.healthit.chpl.certificationId.Validator;
import gov.healthit.chpl.certificationId.ValidatorFactory;
import gov.healthit.chpl.dto.CQMMetDTO;
import gov.healthit.chpl.manager.CertificationIdManager;
import gov.healthit.chpl.manager.CertifiedProductManager;

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

import junit.framework.TestCase;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {
    gov.healthit.chpl.CHPLTestConfig.class
})
@TestExecutionListeners({
        DependencyInjectionTestExecutionListener.class, DirtiesContextTestExecutionListener.class,
        TransactionalTestExecutionListener.class, DbUnitTestExecutionListener.class
})
@DatabaseSetup("classpath:data/testData.xml")
public class CertificationIdTest extends TestCase {

    @Autowired
    private CertifiedProductManager certifiedProductManager;

    @Autowired
    private CertificationIdManager certificationIdManager;

    @Test
    @Transactional
    public void certificationId2014InfoMessagesTest() {

        List<Long> productIdList = new ArrayList<Long>();
        productIdList.add(294L);

        Validator validator = ValidatorFactory.getValidator("2014");

        // Lookup Criteria for Validating
        List<String> criteriaDtos = certificationIdManager.getCriteriaNumbersMetByCertifiedProductIds(productIdList);

        // Lookup CQMs for Validating
        List<CQMMetDTO> cqmDtos = certificationIdManager.getCqmsMetByCertifiedProductIds(productIdList);

        validator.validate(criteriaDtos, cqmDtos, new ArrayList<Integer>(2014));
        assertNotNull(validator.getMissingXOr());
        assertNotNull(validator.getMissingCombo());
        assertNotNull(validator.getMissingOr());
        assertNotNull(validator.getMissingAnd());
    }

    @Test
    @Transactional
    public void certificationId2015InfoMessagesTest() {

        List<Long> productIdList = new ArrayList<Long>();
        productIdList.add(9261L);

        Validator validator = ValidatorFactory.getValidator("2015");

        // Lookup Criteria for Validating
        List<String> criteriaDtos = certificationIdManager.getCriteriaNumbersMetByCertifiedProductIds(productIdList);

        // Lookup CQMs for Validating
        List<CQMMetDTO> cqmDtos = certificationIdManager.getCqmsMetByCertifiedProductIds(productIdList);

        validator.validate(criteriaDtos, cqmDtos, new ArrayList<Integer>(2015));
        assertTrue(validator.getMissingXOr().isEmpty());
        assertTrue(validator.getMissingCombo().isEmpty());
        assertNotNull(validator.getMissingOr());
        assertNotNull(validator.getMissingAnd());
    }

    @Test
    @Transactional
    public void certificationId20142015InfoMessagesTest() {

        List<Long> productIdList = new ArrayList<Long>();
        productIdList.add(294L);
        productIdList.add(9261L);

        Validator validator = ValidatorFactory.getValidator("2014/2015");

        // Lookup Criteria for Validating
        List<String> criteriaDtos = certificationIdManager.getCriteriaNumbersMetByCertifiedProductIds(productIdList);

        // Lookup CQMs for Validating
        List<CQMMetDTO> cqmDtos = certificationIdManager.getCqmsMetByCertifiedProductIds(productIdList);

        validator.validate(criteriaDtos, cqmDtos, new ArrayList<Integer>(2014));
        assertTrue(validator.getMissingXOr().isEmpty());
        assertNotNull(validator.getMissingCombo());
        assertNotNull(validator.getMissingOr());
        assertTrue(validator.getMissingAnd().isEmpty());
    }
}
