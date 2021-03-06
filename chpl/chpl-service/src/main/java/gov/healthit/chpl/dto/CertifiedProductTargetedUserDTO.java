package gov.healthit.chpl.dto;

import java.io.Serializable;

import gov.healthit.chpl.entity.listing.CertifiedProductTargetedUserEntity;

public class CertifiedProductTargetedUserDTO implements Serializable {
    private static final long serialVersionUID = -7651077841236092973L;
    private Long id;
    private Long certifiedProductId;
    private Long targetedUserId;
    private String targetedUserName;

    public CertifiedProductTargetedUserDTO() {
    }

    public CertifiedProductTargetedUserDTO(CertifiedProductTargetedUserEntity entity) {
        this.id = entity.getId();
        this.certifiedProductId = entity.getCertifiedProductId();
        this.targetedUserId = entity.getTargetedUserId();
        if (entity.getTargetedUser() != null) {
            this.targetedUserName = entity.getTargetedUser().getName();
        }
    }

    public Long getId() {
        return id;
    }

    public void setId(final Long id) {
        this.id = id;
    }

    public Long getCertifiedProductId() {
        return certifiedProductId;
    }

    public void setCertifiedProductId(final Long certifiedProductId) {
        this.certifiedProductId = certifiedProductId;
    }

    public Long getTargetedUserId() {
        return targetedUserId;
    }

    public void setTargetedUserId(final Long targetedUserId) {
        this.targetedUserId = targetedUserId;
    }

    public String getTargetedUserName() {
        return targetedUserName;
    }

    public void setTargetedUserName(final String targetedUserName) {
        this.targetedUserName = targetedUserName;
    }
}
