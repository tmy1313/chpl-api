package gov.healthit.chpl.domain;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

import gov.healthit.chpl.dto.CertificationCriterionDTO;

@XmlType(namespace = "http://chpl.healthit.gov/listings")
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificationCriterion implements Serializable {
    private static final long serialVersionUID = 5732322243572571895L;

    @XmlElement(required = false, nillable = true)
    private Long id;

    @XmlElement(required = true)
    private String number;

    @XmlElement(required = false, nillable = true)
    private String title;

    @XmlElement(required = false, nillable = true)
    private Long certificationEditionId;

    @XmlElement(required = false, nillable = true)
    private String certificationEdition;

    @XmlElement(required = false, nillable = true)
    private String description;

    public CertificationCriterion() {
    }

    public CertificationCriterion(CertificationCriterionDTO dto) {
        this.id = dto.getId();
        this.certificationEditionId = dto.getCertificationEditionId();
        this.certificationEdition = dto.getCertificationEdition();
        this.description = dto.getDescription();
        this.number = dto.getNumber();
        this.title = dto.getTitle();
    }

    public String getCertificationEdition() {
        return certificationEdition;
    }

    public void setCertificationEdition(final String certificationEdition) {
        this.certificationEdition = certificationEdition;
    }

    public Long getId() {
        return id;
    }

    public void setId(final Long id) {
        this.id = id;
    }

    public String getNumber() {
        return number;
    }

    public void setNumber(final String number) {
        this.number = number;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(final String title) {
        this.title = title;
    }

    public Long getCertificationEditionId() {
        return certificationEditionId;
    }

    public void setCertificationEditionId(final Long certificationEditionId) {
        this.certificationEditionId = certificationEditionId;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(final String description) {
        this.description = description;
    }
}
