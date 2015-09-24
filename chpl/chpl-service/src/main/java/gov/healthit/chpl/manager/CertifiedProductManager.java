package gov.healthit.chpl.manager;

import gov.healthit.chpl.dao.EntityCreationException;
import gov.healthit.chpl.dao.EntityRetrievalException;
import gov.healthit.chpl.dto.AdditionalSoftwareDTO;
import gov.healthit.chpl.dto.CQMCriterionDTO;
import gov.healthit.chpl.dto.CQMResultDTO;
import gov.healthit.chpl.dto.CertificationCriterionDTO;
import gov.healthit.chpl.dto.CertifiedProductDTO;

import java.util.List;
import java.util.Map;



public interface CertifiedProductManager {

	public CertifiedProductDTO getById(Long id) throws EntityRetrievalException;
	public List<CertifiedProductDTO> getByVersion(Long versionId);
	public List<CertifiedProductDTO> getByVersions(List<Long> versionIds);
	
//	public CertifiedProductDTO create(CertifiedProductDTO dto) throws EntityRetrievalException, EntityCreationException;
	public CertifiedProductDTO update(CertifiedProductDTO dto) throws EntityRetrievalException;
//	public void delete(CertifiedProductDTO dto) throws EntityRetrievalException;
//	public void delete(Long certifiedProductId) throws EntityRetrievalException;
	
	public void replaceCertifications(CertifiedProductDTO dto, Map<CertificationCriterionDTO, Boolean> certResults)
			throws EntityCreationException, EntityRetrievalException;
	public void replaceCqms(CertifiedProductDTO productDto, Map<CQMCriterionDTO, Boolean> cqmResults)
			throws EntityRetrievalException, EntityCreationException;
	public void replaceAdditionalSoftware(CertifiedProductDTO productDto, List<AdditionalSoftwareDTO> newSoftware) 
			throws EntityCreationException;
	
}
