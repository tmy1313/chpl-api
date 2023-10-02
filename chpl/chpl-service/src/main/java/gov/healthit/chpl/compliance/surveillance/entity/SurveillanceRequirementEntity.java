package gov.healthit.chpl.compliance.surveillance.entity;

import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import org.hibernate.annotations.Where;

import gov.healthit.chpl.domain.surveillance.SurveillanceRequirement;
import gov.healthit.chpl.service.CertificationCriterionService;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "surveillance_requirement")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SurveillanceRequirementEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "surveillance_id")
    private Long surveillanceId;

    @OneToOne(optional = true, fetch = FetchType.LAZY)
    @JoinColumn(name = "requirement_type_id")
    private RequirementTypeEntity requirementType;

    @Column(name = "requirement_type_other")
    private String requirementTypeOther;

    @OneToOne(optional = true, fetch = FetchType.LAZY)
    @JoinColumn(name = "result_id")
    private SurveillanceResultTypeEntity surveillanceResultTypeEntity;

    @Column(name = "deleted")
    private Boolean deleted;

    @Column(name = "last_modified_user")
    private Long lastModifiedUser;

    @Column(name = "creation_date", insertable = false, updatable = false)
    private Date creationDate;

    @Column(name = "last_modified_date", insertable = false, updatable = false)
    private Date lastModifiedDate;

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "surveillanceRequirementId")
    @Column(name = "surveillance_requirement_id", nullable = false, insertable = false, updatable = false)
    @Where(clause = "deleted <> 'true'")
    private Set<SurveillanceNonconformityEntity> nonconformities = new HashSet<SurveillanceNonconformityEntity>();

    public SurveillanceRequirement toDomain(CertificationCriterionService certificationCriterionService) {
        SurveillanceRequirement req = SurveillanceRequirement.builder()
                .id(this.getId())
                .nonconformities(Optional.ofNullable(this.getNonconformities()).orElse(Collections.emptySet()).stream()
                        .map(e -> e.toDomain(certificationCriterionService))
                        .toList())
                .requirementType(this.requirementType != null ? this.requirementType.toDomain() : null)
                .requirementTypeOther(this.requirementTypeOther)
                .result(this.getSurveillanceResultTypeEntity() != null ? this.getSurveillanceResultTypeEntity().toDomain() : null)
                .build();
        return req;
    }
}