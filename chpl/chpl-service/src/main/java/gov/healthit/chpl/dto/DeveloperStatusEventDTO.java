package gov.healthit.chpl.dto;

import java.io.Serializable;
import java.util.Date;

import gov.healthit.chpl.entity.developer.DeveloperStatusEventEntity;

/**
 * Developer Status Event DTO.
 * @author alarned
 *
 */
public class DeveloperStatusEventDTO implements Serializable {
    private static final long serialVersionUID = -2492374479266782228L;

    private Long id;
    private Long developerId;
    private DeveloperStatusDTO status;
    private Date statusDate;
    private String reason;

    /** Default constructor. */
    public DeveloperStatusEventDTO() {
    }

    /**
     * Constructed from entity.
     * @param entity the entity
     */
    public DeveloperStatusEventDTO(final DeveloperStatusEventEntity entity) {
        this();
        this.id = entity.getId();
        this.developerId = entity.getDeveloperId();
        this.status = new DeveloperStatusDTO(entity.getDeveloperStatus());
        this.statusDate = entity.getStatusDate();
        this.reason = entity.getReason();
    }

    public Long getId() {
        return id;
    }

    public void setId(final Long id) {
        this.id = id;
    }

    public Long getDeveloperId() {
        return developerId;
    }

    public void setDeveloperId(final Long developerId) {
        this.developerId = developerId;
    }

    public Date getStatusDate() {
        return statusDate;
    }

    public void setStatusDate(final Date statusDate) {
        this.statusDate = statusDate;
    }

    public DeveloperStatusDTO getStatus() {
        return status;
    }

    public void setStatus(final DeveloperStatusDTO status) {
        this.status = status;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(final String reason) {
        this.reason = reason;
    }

    /**
     * Return true iff this DTO matches a different on.
     * @param anotherStatusEvent the different one
     * @return true iff this matches
     */
    public boolean matches(final DeveloperStatusEventDTO anotherStatusEvent) {
        boolean result = false;
        if (this.getId() != null && anotherStatusEvent.getId() != null
                && this.getId().longValue() == anotherStatusEvent.getId().longValue()) {
            return true;
        }
        return result;
    }

    @Override
    public String toString() {
        return "Developer Status Event DTO: ["
                + "[Developer ID: " + this.developerId + "] "
                + "[Status Date: " + this.statusDate.toString() + "] "
                + "[Status: " + this.status.getStatusName() + "] "
                + "[Reason: " + this.reason + "]"
                + "]";
    }
}
