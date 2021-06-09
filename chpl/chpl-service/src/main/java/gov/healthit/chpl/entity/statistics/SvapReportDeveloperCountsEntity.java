package gov.healthit.chpl.entity.statistics;

import java.util.Date;

import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import gov.healthit.chpl.entity.CertificationBodyEntity;
import gov.healthit.chpl.entity.developer.DeveloperEntity;
import gov.healthit.chpl.scheduler.job.svapreports.SvapReportDeveloperCounts;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Entity
@Data
@Builder
@AllArgsConstructor
@Table(name = "svap_report_developer_counts")
public class SvapReportDeveloperCountsEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "id", nullable = false)
    private Long id;

    @Basic(optional = false)
    @Column(name = "certification_body_id", nullable = false)
    private Long certificationBodyId;

    @OneToOne(optional = true, fetch = FetchType.LAZY)
    @JoinColumn(name = "certification_body_id", insertable = false, updatable = false)
    private CertificationBodyEntity certificationBody;

    @Basic(optional = false)
    @Column(name = "developer_id", nullable = false)
    private Long developerId;

    @OneToOne(optional = true, fetch = FetchType.LAZY)
    @JoinColumn(name = "developer_id", insertable = false, updatable = false)
    private DeveloperEntity developer;

    @Basic(optional = false)
    @Column(name = "listing_count", nullable = false)
    private Integer listingCount;

    @Basic(optional = false)
    @Column(name = "criteria_count", nullable = false)
    private Integer criteriaCount;

    @Basic(optional = false)
    @Column(name = "svap_count", nullable = false)
    private Integer svapCount;

    @Basic(optional = false)
    @Column(name = "creation_date", nullable = false)
    private Date creationDate;

    @Basic(optional = false)
    @Column(name = "deleted", nullable = false)
    private Boolean deleted;

    @Basic(optional = false)
    @Column(name = "last_modified_date", nullable = false)
    private Date lastModifiedDate;

    @Basic(optional = false)
    @Column(name = "last_modified_user", nullable = false)
    private Long lastModifiedUser;

    public SvapReportDeveloperCounts toDomain() {
        return SvapReportDeveloperCounts.builder()
                .id(this.getId())
                .certificationBodyId(this.getCertificationBodyId())
                .acb(this.getCertificationBody().getName())
                .developerId(this.getDeveloperId())
                .developerName(this.getDeveloper().getName())
                .listingCount(this.getListingCount())
                .criteriaCount(this.getCriteriaCount())
                .svapCount(this.getSvapCount())
                .build();
    }
}
