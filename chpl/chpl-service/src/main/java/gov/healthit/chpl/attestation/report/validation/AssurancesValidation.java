package gov.healthit.chpl.attestation.report.validation;

import java.util.List;

import gov.healthit.chpl.manager.rules.ValidationRule;

public class AssurancesValidation extends ValidationRule<AttestationValidationContext> {

    @Override
    public boolean isValid(AttestationValidationContext context) {
        List<Long> assurancesCriteriaIds = context.getAssuranceCriteria().stream()
                .map(crit -> crit.getId())
                .toList();

        return context.getListings().stream()
                .filter(listing -> context.getActiveStatuses().contains(listing.getCertificationStatus()))
                .flatMap(listing -> listing.getCriteriaMet().stream())
                .filter(criteriaMetId -> assurancesCriteriaIds.contains(criteriaMetId))
                .findAny()
                .isPresent();
    }

}
