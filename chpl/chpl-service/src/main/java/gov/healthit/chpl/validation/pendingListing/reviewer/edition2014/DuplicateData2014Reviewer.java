package gov.healthit.chpl.validation.pendingListing.reviewer.edition2014;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import gov.healthit.chpl.dto.PendingCertificationResultDTO;
import gov.healthit.chpl.dto.PendingCertifiedProductDTO;
import gov.healthit.chpl.validation.pendingListing.reviewer.Reviewer;
import gov.healthit.chpl.validation.pendingListing.reviewer.duplicate.TestFunctionalityDuplicateReviewer;
import gov.healthit.chpl.validation.pendingListing.reviewer.duplicate.TestToolDuplicateReviewer;
import gov.healthit.chpl.validation.pendingListing.reviewer.edition2014.duplicate.AdditionalSoftware2014DuplicateReviewer;
import gov.healthit.chpl.validation.pendingListing.reviewer.edition2014.duplicate.QmsStandard2014DuplicateReviewer;
import gov.healthit.chpl.validation.pendingListing.reviewer.edition2014.duplicate.TestData2014DuplicateReviewer;
import gov.healthit.chpl.validation.pendingListing.reviewer.edition2014.duplicate.TestProcedure2014DuplicateReviewer;

@Component("pendingDuplicateData2014Reviewer")
public class DuplicateData2014Reviewer implements Reviewer {
    private static final Logger LOGGER = LogManager.getLogger(DuplicateData2014Reviewer.class);

    private QmsStandard2014DuplicateReviewer qmsStandardDuplicateReviewer;
    private TestFunctionalityDuplicateReviewer testFunctionalityDuplicateReviewer;
    private AdditionalSoftware2014DuplicateReviewer additionalSoftwareDuplicateReviewer;
    private TestToolDuplicateReviewer testToolDuplicateReviewer;
    private TestProcedure2014DuplicateReviewer testProcedureDuplicateReviewer;
    private TestData2014DuplicateReviewer testDataDuplicateReviewer;

    @Autowired
    public DuplicateData2014Reviewer(QmsStandard2014DuplicateReviewer qmsStandard2014DuplicateReviewer,
            TestFunctionalityDuplicateReviewer testFunctionalityDuplicateReviewer,
            AdditionalSoftware2014DuplicateReviewer additionalSoftwareDuplicateReviewer,
            TestToolDuplicateReviewer testToolDuplicateReviewer,
            TestProcedure2014DuplicateReviewer testProcedureDuplicateReviewer,
            TestData2014DuplicateReviewer testDataDuplicateReviewer) {
        this.qmsStandardDuplicateReviewer = qmsStandard2014DuplicateReviewer;
        this.testFunctionalityDuplicateReviewer = testFunctionalityDuplicateReviewer;
        this.additionalSoftwareDuplicateReviewer = additionalSoftwareDuplicateReviewer;
        this.testToolDuplicateReviewer = testToolDuplicateReviewer;
        this.testProcedureDuplicateReviewer = testProcedureDuplicateReviewer;
        this.testDataDuplicateReviewer = testDataDuplicateReviewer;
    }

    @Override
    public void review(PendingCertifiedProductDTO listing) {
        qmsStandardDuplicateReviewer.review(listing);

        for (PendingCertificationResultDTO pcr : listing.getCertificationCriterion()) {
            testFunctionalityDuplicateReviewer.review(listing, pcr);
            additionalSoftwareDuplicateReviewer.review(listing, pcr);
            testToolDuplicateReviewer.review(listing, pcr);
            testProcedureDuplicateReviewer.review(listing, pcr);
            testDataDuplicateReviewer.review(listing, pcr);
        }
    }


}
