package gov.healthit.chpl.validation.listing.reviewer.edition2014;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import gov.healthit.chpl.domain.CertificationResult;
import gov.healthit.chpl.domain.CertifiedProductSearchDetails;
import gov.healthit.chpl.util.CertificationResultRules;
import gov.healthit.chpl.util.ValidationUtils;
import gov.healthit.chpl.validation.listing.reviewer.Reviewer;

@Component("ambulatoryRequiredTestToolReviewer")
public class AmbulatoryRequiredTestToolReviewer implements Reviewer {
    private static final String[] TEST_TOOL_CHECK_CERTS = {
            "170.314 (g)(1)", "170.314 (g)(2)", "170.314 (f)(3)"
    };
    
    @Autowired private CertificationResultRules certRules;
    
    @Override
    public void review(CertifiedProductSearchDetails listing) {
        for (CertificationResult cert : listing.getCertificationResults()) {
            if (cert.isSuccess() != null && cert.isSuccess() == Boolean.TRUE) {
                boolean gapEligibleAndTrue = false;
                if (certRules.hasCertOption(cert.getNumber(), CertificationResultRules.GAP)
                        && cert.isGap() == Boolean.TRUE) {
                    gapEligibleAndTrue = true;
                }

                if (!gapEligibleAndTrue
                        && certRules.hasCertOption(cert.getNumber(), CertificationResultRules.TEST_TOOLS_USED)
                        && ValidationUtils.containsCert(cert, TEST_TOOL_CHECK_CERTS)
                        && (cert.getTestToolsUsed() == null || cert.getTestToolsUsed().size() == 0)) {
                    listing.getErrorMessages()
                        .add("Test Tools are required for certification " + cert.getNumber() + ".");
                }
            }
        }
    }
}
