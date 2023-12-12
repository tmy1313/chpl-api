package gov.healthit.chpl.entity.listing;

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

import gov.healthit.chpl.accessibilityStandard.AccessibilityStandardEntity;
import gov.healthit.chpl.entity.EntityAudit;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@ToString
@SuperBuilder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "certified_product_accessibility_standard")
public class CertifiedProductAccessibilityStandardEntity extends EntityAudit {
    private static final long serialVersionUID = -2757478774638660385L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "certified_product_accessibility_standard_id")
    private Long id;

    @Basic(optional = false)
    @Column(name = "certified_product_id", nullable = false)
    private Long certifiedProductId;

    @Basic(optional = false)
    @Column(name = "accessibility_standard_id", nullable = false)
    private Long accessibilityStandardId;

    @Basic(optional = true)
    @OneToOne(optional = true, fetch = FetchType.LAZY)
    @JoinColumn(name = "accessibility_standard_id", unique = true, nullable = true, insertable = false,
            updatable = false)
    private AccessibilityStandardEntity accessibilityStandard;

}
