package gov.healthit.chpl.dao.impl;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.persistence.Query;

import org.springframework.stereotype.Repository;

import gov.healthit.chpl.auth.Util;
import gov.healthit.chpl.dao.CertifiedProductAccessibilityStandardDAO;
import gov.healthit.chpl.dao.EntityCreationException;
import gov.healthit.chpl.dao.EntityRetrievalException;
import gov.healthit.chpl.dto.CertifiedProductAccessibilityStandardDTO;
import gov.healthit.chpl.entity.CertifiedProductAccessibilityStandardEntity;

@Repository(value="certifiedProductAccessibilityStandardDao")
public class CertifiedProductAccessibilityStandardDAOImpl extends BaseDAOImpl 
	implements CertifiedProductAccessibilityStandardDAO {

	@Override
	public CertifiedProductAccessibilityStandardDTO createCertifiedProductAccessibilityStandard(CertifiedProductAccessibilityStandardDTO toCreate) throws EntityCreationException {
		
		CertifiedProductAccessibilityStandardEntity toCreateEntity = new CertifiedProductAccessibilityStandardEntity();
		toCreateEntity.setCertifiedProductId(toCreate.getCertifiedProductId());
		toCreateEntity.setAccessibilityStandardId(toCreate.getAccessibilityStandardId());
		toCreateEntity.setLastModifiedDate(new Date());
		toCreateEntity.setLastModifiedUser(Util.getCurrentUser().getId());
		toCreateEntity.setCreationDate(new Date());
		toCreateEntity.setDeleted(false);
		entityManager.persist(toCreateEntity);
		entityManager.flush();

		return new CertifiedProductAccessibilityStandardDTO(toCreateEntity);
	}
	
	@Override
	public CertifiedProductAccessibilityStandardDTO deleteCertifiedProductAccessibilityStandards(Long id) throws EntityRetrievalException {
		
		CertifiedProductAccessibilityStandardEntity curr = getEntityById(id);
		if(curr == null) {
			throw new EntityRetrievalException("Could not find mapping with id " + id);
		}
		curr.setDeleted(true);
		curr.setLastModifiedDate(new Date());
		curr.setLastModifiedUser(Util.getCurrentUser().getId());
		entityManager.persist(curr);
		entityManager.flush();

		return new CertifiedProductAccessibilityStandardDTO(curr);
	}
	
	@Override
	public List<CertifiedProductAccessibilityStandardDTO> getAccessibilityStandardsByCertifiedProductId(Long certifiedProductId)
			throws EntityRetrievalException {
		List<CertifiedProductAccessibilityStandardEntity> entities = getEntitiesByCertifiedProductId(certifiedProductId);
		List<CertifiedProductAccessibilityStandardDTO> dtos = new ArrayList<CertifiedProductAccessibilityStandardDTO>();
		
		for (CertifiedProductAccessibilityStandardEntity entity : entities){
			dtos.add(new CertifiedProductAccessibilityStandardDTO(entity));
		}
		return dtos;
	}
	
	private CertifiedProductAccessibilityStandardEntity getEntityById(Long id) throws EntityRetrievalException {
		CertifiedProductAccessibilityStandardEntity entity = null;
		Query query = entityManager.createQuery( "SELECT as from CertifiedProductAccessibilityStandardEntity as "
				+ "LEFT OUTER JOIN FETCH as.accessibilityStandard "
				+ "where (NOT as.deleted = true) AND (id = :entityid) ", 
				CertifiedProductAccessibilityStandardEntity.class );

		query.setParameter("entityid", id);
		List<CertifiedProductAccessibilityStandardEntity> result = query.getResultList();
		if(result.size() >= 1) {
			entity = result.get(0);
		} 
		return entity;
	}
	
	private List<CertifiedProductAccessibilityStandardEntity> getEntitiesByCertifiedProductId(Long productId) throws EntityRetrievalException {
		Query query = entityManager.createQuery( "SELECT as from CertifiedProductAccessibilityStandardEntity as "
				+ "LEFT OUTER JOIN FETCH as.accessibilityStandard "
				+ "where (NOT as.deleted = true) AND (certified_product_id = :entityid) ", 
				CertifiedProductAccessibilityStandardEntity.class );

		query.setParameter("entityid", productId);
		List<CertifiedProductAccessibilityStandardEntity> result = query.getResultList();
		
		return result;
	}
	
}
