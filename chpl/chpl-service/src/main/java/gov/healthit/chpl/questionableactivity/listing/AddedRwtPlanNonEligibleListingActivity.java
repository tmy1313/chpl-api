package gov.healthit.chpl.questionableactivity.listing;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import gov.healthit.chpl.domain.CertifiedProductSearchDetails;
import gov.healthit.chpl.domain.concept.QuestionableActivityTriggerConcept;
import gov.healthit.chpl.dto.questionableActivity.QuestionableActivityListingDTO;
import gov.healthit.chpl.service.realworldtesting.RealWorldTestingEligiblityServiceFactory;
import lombok.extern.log4j.Log4j2;

@Log4j2
@Component
public class AddedRwtPlanNonEligibleListingActivity implements ListingActivity {
    private RealWorldTestingEligiblityServiceFactory rwtEligServiceFactory;

    @Autowired
    public AddedRwtPlanNonEligibleListingActivity(RealWorldTestingEligiblityServiceFactory rwtEligServiceFactory) {
        this.rwtEligServiceFactory = rwtEligServiceFactory;
    }

    @Override
    public List<QuestionableActivityListingDTO> check(CertifiedProductSearchDetails origListing, CertifiedProductSearchDetails newListing) {
        QuestionableActivityListingDTO activity = null;
        if (StringUtils.isEmpty(origListing.getRwtPlansUrl())
                && !StringUtils.isEmpty(newListing.getRwtPlansUrl())
                && !isListingRealWorldTestingEligible(newListing.getId())) {
            activity = new QuestionableActivityListingDTO();
            activity.setAfter("Added Plans URL " + newListing.getRwtPlansUrl());
        }
        return Arrays.asList(activity);
    }

    @Override
    public QuestionableActivityTriggerConcept getTriggerType() {
        return QuestionableActivityTriggerConcept.REAL_WORLD_TESTING_ADDED;
    }

    private boolean isListingRealWorldTestingEligible(Long listingId) {
        return rwtEligServiceFactory.getInstance().getRwtEligibilityYearForListing(listingId, LOGGER).getEligibilityYear() != null;
    }
}