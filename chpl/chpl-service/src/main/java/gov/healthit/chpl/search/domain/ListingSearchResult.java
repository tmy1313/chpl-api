package gov.healthit.chpl.search.domain;

import java.io.Serializable;
import java.time.LocalDate;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.ObjectUtils;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import gov.healthit.chpl.domain.CertificationEdition;
import gov.healthit.chpl.util.LocalDateDeserializer;
import gov.healthit.chpl.util.LocalDateSerializer;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@Builder
@AllArgsConstructor
public class ListingSearchResult implements Serializable {

    private static final long serialVersionUID = -254739051764841038L;
    public static final String SMILEY_SPLIT_CHAR = "\u263A";
    public static final String FROWNEY_SPLIT_CHAR = "\u2639";

    private Long id;
    private String chplProductNumber;
    private IdNamePair edition;
    private IdNamePair certificationBody;
    private String acbCertificationId;
    private IdNamePair practiceType;
    private Developer developer;
    private IdNamePair product;
    private IdNamePair version;
    @JsonDeserialize(using = LocalDateDeserializer.class)
    @JsonSerialize(using = LocalDateSerializer.class)
    private LocalDate certificationDate;
    @JsonDeserialize(using = LocalDateDeserializer.class)
    @JsonSerialize(using = LocalDateSerializer.class)
    private LocalDate decertificationDate;
    private IdNamePair certificationStatus;
    private Boolean curesUpdate;
    private Long surveillanceCount;
    private Long openSurveillanceNonConformityCount;
    private Long closedSurveillanceNonConformityCount;
    @Builder.Default
    private Integer directReviewCount = 0;
    @Builder.Default
    private Integer openDirectReviewNonConformityCount = 0;
    @Builder.Default
    private Integer closedDirectReviewNonConformityCount = 0;
    private Long openSurveillanceCount;
    private Long closedSurveillanceCount;
    private PromotingInteroperability promotingInteroperability;
    private String mandatoryDisclosures;
    private Set<IdNamePair> previousDevelopers;
    private Set<CertificationCriterion> criteriaMet;
    private Set<CQM> cqmsMet;
    private Set<DateRange> surveillanceDateRanges;
    private Set<StatusEvent> statusEvents;
    private Set<CertificationCriterionWithStringField> apiDocumentation;
    private CertificationCriterionWithStringField serviceBaseUrlList;
    private String rwtPlansUrl;
    private String rwtResultsUrl;

    public ListingSearchResult() {
        this.setDirectReviewCount(0);
        this.setSurveillanceCount(0L);
        this.setOpenDirectReviewNonConformityCount(0);
        this.setClosedDirectReviewNonConformityCount(0);
        this.setOpenSurveillanceCount(0L);
        this.setClosedSurveillanceCount(0L);
        this.setOpenSurveillanceNonConformityCount(0L);
        this.setClosedSurveillanceNonConformityCount(0L);
        previousDevelopers = new HashSet<IdNamePair>();
        criteriaMet = new HashSet<CertificationCriterion>();
        cqmsMet = new HashSet<CQM>();
        surveillanceDateRanges = new HashSet<DateRange>();
        statusEvents = new HashSet<StatusEvent>();
        apiDocumentation = new HashSet<CertificationCriterionWithStringField>();
    }

    @Override
    public boolean equals(Object another) {
        if (another == null) {
            return false;
        }
        if (!(another instanceof ListingSearchResult)) {
            return false;
        }
        ListingSearchResult anotherSearchResult = (ListingSearchResult) another;
        if (ObjectUtils.allNotNull(this, anotherSearchResult, this.getId(), anotherSearchResult.getId())) {
            return Objects.equals(this.getId(), anotherSearchResult.getId());
        }
        return false;
    }

    @Override
    public int hashCode() {
        if (this.getId() == null) {
            return -1;
        }
        return this.getId().hashCode();
    }

    @JsonIgnore
    public String getDerivedEdition() {
        return getEdition().getName() + (BooleanUtils.isTrue(getCuresUpdate()) ? CertificationEdition.CURES_SUFFIX : "");
    }


    @Getter
    @SuperBuilder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class IdNamePair {
        private Long id;
        private String name;
    }

    @Getter
    @SuperBuilder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Developer extends IdNamePair {
        private IdNamePair status;
    }

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PromotingInteroperability {
        private Long userCount;
        @JsonDeserialize(using = LocalDateDeserializer.class)
        @JsonSerialize(using = LocalDateSerializer.class)
        private LocalDate userDate;
    }

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CertificationCriterion {
        private Long id;
        private String number;
        private String title;
    }

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CertificationCriterionWithStringField {
        private CertificationCriterion criterion;
        private String value;
    }

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CQM {
        private Long id;
        private String number;
    }

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class StatusEvent {
        @JsonDeserialize(using = LocalDateDeserializer.class)
        @JsonSerialize(using = LocalDateSerializer.class)
        private LocalDate statusStart;
        private IdNamePair status;
    }

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DateRange {
        @JsonDeserialize(using = LocalDateDeserializer.class)
        @JsonSerialize(using = LocalDateSerializer.class)
        private LocalDate start;
        @JsonDeserialize(using = LocalDateDeserializer.class)
        @JsonSerialize(using = LocalDateSerializer.class)
        private LocalDate end;
    }
}
