package gov.healthit.chpl.dao.search;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.persistence.Query;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import gov.healthit.chpl.dao.CertificationResultDAO;
import gov.healthit.chpl.dao.impl.BaseDAOImpl;
import gov.healthit.chpl.domain.search.BasicSearchResponse;
import gov.healthit.chpl.domain.search.CertifiedProductBasicSearchResult;
import gov.healthit.chpl.entity.CertificationResultEntity;
import gov.healthit.chpl.entity.search.BasicCQMResultEntity;
import gov.healthit.chpl.entity.search.BasicCertificationResultEntity;
import gov.healthit.chpl.entity.search.CertifiedProductBasicSearchResultEntity;
import gov.healthit.chpl.manager.impl.InvitationManagerImpl;

@Repository("certifiedProductSearchDAO")
public class CertifiedProductSearchDAOImpl extends BaseDAOImpl implements CertifiedProductSearchDAO {
	private static final Logger logger = LogManager.getLogger(CertifiedProductSearchDAOImpl.class);
	
	@Autowired private CertificationResultDAO certDao;
	
	public List<CertifiedProductBasicSearchResult> getAllCertifiedProducts() {
		Query query = entityManager.createQuery("SELECT cps "
				+ "FROM CertifiedProductBasicSearchResultEntity cps "
//				+ "LEFT JOIN FETCH cps.certificationResults certResults "
//				+ "LEFT JOIN FETCH certResults.certificationCriterion cert "
//				+ "LEFT JOIN FETCH cert.certificationEdition "
//				+ "LEFT JOIN FETCH cps.cqmResults cqmResults "
//				+ "LEFT JOIN FETCH cqmResults.cqmCriterion cqm "
//				+ "LEFT JOIN FETCH cqm.cqmVersion "
				, CertifiedProductBasicSearchResultEntity.class);
		
		Date startDate = new Date();
		List<CertifiedProductBasicSearchResultEntity> results = query.getResultList();
		Date endDate = new Date();
		logger.info("Got query results in " + (endDate.getTime() - startDate.getTime()) + " millis");
		return convert(results);
	}
	
	private List<CertifiedProductBasicSearchResult> convert(List<CertifiedProductBasicSearchResultEntity> dbResults) {
		List<CertifiedProductBasicSearchResult> results = new ArrayList<CertifiedProductBasicSearchResult>(dbResults.size());
		for(CertifiedProductBasicSearchResultEntity dbResult : dbResults) {
			CertifiedProductBasicSearchResult result = new CertifiedProductBasicSearchResult();
			result.setId(dbResult.getId());
			result.setChplProductNumber(dbResult.getChplProductNumber());
			result.setEdition(dbResult.getEdition());
			result.setAtl(dbResult.getAtlName());
			result.setAcb(dbResult.getAcbName());
			result.setPracticeType(dbResult.getPracticeTypeName());
			result.setDeveloper(dbResult.getDeveloper());
			result.setProduct(dbResult.getProduct());
			result.setVersion(dbResult.getVersion());
			result.setCertificationDate(dbResult.getCertificationDate().getTime());
			result.setCertificationStatus(dbResult.getCertificationStatus());
			result.setHasHadSurveillance(dbResult.getHasHadSurveillance());
			result.setHasOpenSurveillance(dbResult.getHasOpenSurveillance());
			result.setHasOpenNonconformities(dbResult.getHasOpenNonconformities());
			
			if(!StringUtils.isEmpty(dbResult.getCerts())) {
				String[] splitCerts = dbResult.getCerts().split(",");
				if(splitCerts != null && splitCerts.length > 0) {
					for(int i = 0; i < splitCerts.length; i++) {
						result.getCriteriaMet().add(splitCerts[i].trim());
					}
				}
			}
			
			if(!StringUtils.isEmpty(dbResult.getCqms())) {
				String[] splitCqms = dbResult.getCqms().split(",");
				if(splitCqms != null && splitCqms.length > 0) {
					for(int i = 0; i < splitCqms.length; i++) {
						result.getCqmsMet().add(splitCqms[i].trim());
					}
				}
			}
			
			results.add(result);
		}
		return results;
	}
}
