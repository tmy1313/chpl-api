package gov.healthit.chpl.changerequest.entity;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.MapsId;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import org.apache.commons.collections4.CollectionUtils;
import org.hibernate.annotations.Immutable;
import org.hibernate.annotations.Where;

import gov.healthit.chpl.attestation.entity.DeveloperAttestationSubmissionEntity;
import gov.healthit.chpl.domain.Developer;
import gov.healthit.chpl.domain.DeveloperStatusEvent;
import gov.healthit.chpl.domain.PublicAttestation;
import gov.healthit.chpl.domain.concept.PublicAttestationStatus;
import gov.healthit.chpl.entity.AddressEntity;
import gov.healthit.chpl.entity.ContactEntity;
import gov.healthit.chpl.entity.developer.DeveloperCertificationStatusesEntity;
import gov.healthit.chpl.entity.developer.DeveloperStatusEventEntity;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Entity
@Table(name = "vendor")
@Immutable
@Getter
@Setter
@ToString
public class DeveloperWithCertificationBodyMapsEntity implements Serializable {
    private static final long serialVersionUID = -2690954398341231989L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "vendor_id", nullable = false)
    private Long id;

    @Column(name = "vendor_code", insertable = false, updatable = false)
    private String developerCode;

    @Column(name = "name")
    private String name;

    @Basic(optional = true)
    @Column(length = 300, nullable = true)
    private String website;

    @Column(name = "self_developer")
    private Boolean selfDeveloper;

    @Basic(optional = true)
    @Column(name = "address_id")
    private Long addressId;

    @Basic(optional = true)
    @OneToOne(optional = true, fetch = FetchType.LAZY)
    @JoinColumn(name = "address_id", unique = true, nullable = true, insertable = false, updatable = false)
    @Where(clause = "deleted <> 'true'")
    private AddressEntity address;

    @Basic(optional = true)
    @Column(name = "contact_id")
    private Long contactId;

    @Basic(optional = true)
    @OneToOne(optional = true, fetch = FetchType.LAZY)
    @JoinColumn(name = "contact_id", unique = true, nullable = true, insertable = false, updatable = false)
    private ContactEntity contact;

    @Basic(optional = false)
    @Column(name = "creation_date", insertable = false, updatable = false)
    private Date creationDate;

    @Column(name = "deleted", insertable = false)
    private Boolean deleted;

    @Column(name = "last_modified_date", insertable = false, updatable = false)
    private Date lastModifiedDate;

    @Basic(optional = false)
    @Column(name = "last_modified_user", nullable = false)
    private Long lastModifiedUser;

    @Basic(optional = true)
    @OneToOne(optional = true, fetch = FetchType.LAZY)
    @MapsId("id")
    @JoinColumn(name = "vendor_id", unique = true, nullable = true, insertable = false, updatable = false)
    private DeveloperCertificationStatusesEntity developerCertificationStatuses;

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "developerId")
    @Basic(optional = false)
    @Column(name = "vendor_id", nullable = false)
    @Where(clause = "deleted <> 'true'")
    private Set<DeveloperStatusEventEntity> statusEvents = new LinkedHashSet<DeveloperStatusEventEntity>();

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "developer")
    @Basic(optional = false)
    @Column(name = "developer_id", nullable = false)
    @Where(clause = "deleted <> 'true'")
    private Set<DeveloperAttestationSubmissionEntity> publicAttestations = new LinkedHashSet<DeveloperAttestationSubmissionEntity>();

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "developerId")
    @Basic(optional = false)
    @Column(name = "vendor_id", nullable = false)
    private Set<DeveloperCertificationBodyMapEntity> certificationBodyMaps = new LinkedHashSet<DeveloperCertificationBodyMapEntity>();

    public Developer toDomain() {
        return Developer.builder()
                .developerId(this.getId())
                .id(this.getId())
                .address(this.getAddress() != null ? this.getAddress().toDomain() : null)
                .contact(this.getContact() != null ? this.getContact().toDomain() : null)
                .deleted(this.getDeleted())
                .developerCode(this.getDeveloperCode())
                .name(this.getName())
                .selfDeveloper(this.getSelfDeveloper())
                .statusEvents(toStatusEventDomains())
                .lastModifiedDate(this.getLastModifiedDate().getTime() + "")
                .website(this.getWebsite())
                .attestations(toPublicAttestationDomains())
                .build();
    }

    private List<DeveloperStatusEvent> toStatusEventDomains() {
        if (CollectionUtils.isEmpty(this.getStatusEvents())) {
            return new ArrayList<DeveloperStatusEvent>();
        }
        return this.statusEvents.stream()
                .map(statusEvent -> statusEvent.toDomain())
                .collect(Collectors.toList());
    }

    private List<PublicAttestation> toPublicAttestationDomains() {
        if (CollectionUtils.isEmpty(this.getPublicAttestations())) {
            return new ArrayList<PublicAttestation>();
        }
        return this.publicAttestations.stream()
                .map(entity -> PublicAttestation.builder()
                        .id(entity.getId())
                        .attestationPeriod(entity.getPeriod() == null ? null : entity.getPeriod().toDomain())
                        .status(PublicAttestationStatus.ATTESTATIONS_SUBMITTED)
                        .build())
                .toList();
    }
}
