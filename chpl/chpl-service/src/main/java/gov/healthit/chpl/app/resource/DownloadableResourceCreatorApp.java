package gov.healthit.chpl.app.resource;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.support.AbstractApplicationContext;

import gov.healthit.chpl.app.App;
import gov.healthit.chpl.dao.CertificationCriterionDAO;
import gov.healthit.chpl.dao.CertificationResultDAO;
import gov.healthit.chpl.dao.CertifiedProductDAO;
import gov.healthit.chpl.dao.EntityRetrievalException;
import gov.healthit.chpl.domain.CertifiedProductDownloadResponse;
import gov.healthit.chpl.domain.CertifiedProductSearchDetails;
import gov.healthit.chpl.dto.CertifiedProductDetailsDTO;
import gov.healthit.chpl.manager.CertifiedProductDetailsManager;

public abstract class DownloadableResourceCreatorApp extends App {
    private static final Logger LOGGER = LogManager.getLogger(DownloadableResourceCreatorApp.class);

    protected SimpleDateFormat timestampFormat;
    protected CertifiedProductDetailsManager cpdManager;
    protected CertifiedProductDAO certifiedProductDao;
    protected CertificationCriterionDAO criteriaDao;
    protected CertificationResultDAO certificationResultDao;

    public DownloadableResourceCreatorApp() {
        timestampFormat = new SimpleDateFormat("yyyyMMdd_HHmmss");
    }

    protected void initiateSpringBeans(AbstractApplicationContext context) throws IOException {
        //this.setCpdManager((CertifiedProductDetailsManager) context.getBean("certifiedProductDetailsManager"));
        this.setCertifiedProductDao((CertifiedProductDAO) context.getBean("certifiedProductDAO"));
        this.setCriteriaDao((CertificationCriterionDAO) context.getBean("certificationCriterionDAO"));
        this.setCertificationResultDao((CertificationResultDAO) context.getBean("certificationResultDAO"));
    }
    
    protected abstract void runJob(String[] args) throws Exception;

    public CertifiedProductDAO getCertifiedProductDao() {
        return certifiedProductDao;
    }

    public void setCertifiedProductDao(final CertifiedProductDAO certifiedProductDAO) {
        this.certifiedProductDao = certifiedProductDAO;
    }

    public SimpleDateFormat getTimestampFormat() {
        return timestampFormat;
    }

    public void setTimestampFormat(final SimpleDateFormat timestampFormat) {
        this.timestampFormat = timestampFormat;
    }

    public CertifiedProductDetailsManager getCpdManager() {
        return cpdManager;
    }

    public void setCpdManager(final CertifiedProductDetailsManager cpdManager) {
        this.cpdManager = cpdManager;
    }

    public CertificationCriterionDAO getCriteriaDao() {
        return criteriaDao;
    }

    public void setCriteriaDao(final CertificationCriterionDAO criteriaDao) {
        this.criteriaDao = criteriaDao;
    }

	public CertificationResultDAO getCertificationResultDao() {
		return certificationResultDao;
	}

	public void setCertificationResultDao(
			CertificationResultDAO certificationResultDao) {
		this.certificationResultDao = certificationResultDao;
	}
}
