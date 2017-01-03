package gov.healthit.chpl.domain;

import java.io.Serializable;

import org.springframework.util.StringUtils;

import gov.healthit.chpl.dto.CertifiedProductDetailsDTO;

public class CertifiedProduct implements Serializable {
	private static final long serialVersionUID = -6634520925641244762L;
	private Long id;
    private String chplProductNumber;
	private String lastModifiedDate;
	private String edition;
	
	public CertifiedProduct() {}
	
	public CertifiedProduct(CertifiedProductDetailsDTO dto) {
		this.id = dto.getId();
		if(!StringUtils.isEmpty(dto.getChplProductNumber())) {
			this.setChplProductNumber(dto.getChplProductNumber());
		} else {
			this.setChplProductNumber(dto.getYearCode() + "." + dto.getTestingLabCode() + "." + dto.getCertificationBodyCode() + "." + 
					dto.getDeveloper().getDeveloperCode() + "." + dto.getProductCode() + "." + dto.getVersionCode() + 
					"." + dto.getIcsCode() + "." + dto.getAdditionalSoftwareCode() + 
					"." + dto.getCertifiedDateCode());
		}
		this.setLastModifiedDate(dto.getLastModifiedDate().getTime() + "");
		this.edition = dto.getYear();
	}
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public String getChplProductNumber() {
		return chplProductNumber;
	}
	public void setChplProductNumber(String chplProductNumber) {
		this.chplProductNumber = chplProductNumber;
	}
	public String getLastModifiedDate() {
		return lastModifiedDate;
	}
	public void setLastModifiedDate(String lastModifiedDate) {
		this.lastModifiedDate = lastModifiedDate;
	}

	public String getEdition() {
		return edition;
	}

	public void setEdition(String edition) {
		this.edition = edition;
	}
}
