package gov.healthit.chpl.scheduler.job.svapreports;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.quartz.DisallowConcurrentExecution;
import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import gov.healthit.chpl.certifiedproduct.CertifiedProductDetailsManager;
import gov.healthit.chpl.dao.CertifiedProductDAO;
import gov.healthit.chpl.dao.statistics.SvapReportDeveloperCountsDAO;
import gov.healthit.chpl.domain.CertifiedProductSearchDetails;
import gov.healthit.chpl.domain.concept.CertificationEditionConcept;
import gov.healthit.chpl.dto.CertifiedProductDetailsDTO;
import gov.healthit.chpl.exception.EntityRetrievalException;
import lombok.extern.log4j.Log4j2;

@DisallowConcurrentExecution
@Log4j2
public class SvapReportsCreatorJob  implements Job {
    @Autowired
    private CertifiedProductDAO certifiedProductDAO;

    @Autowired
    private SvapReportDeveloperCountsDAO svapReportDeveloperCountsDao;

    @Autowired
    private CertifiedProductDetailsManager certifiedProductDetailsManager;

    @Override
    public void execute(JobExecutionContext jobContext) throws JobExecutionException {
        SpringBeanAutowiringSupport.processInjectionBasedOnCurrentContext(this);

        List<CertifiedProductSearchDetails> listings = getAll2015Listings();

        generateDevelopersWithSvapStatistics(listings);
    }

    private void generateDevelopersWithSvapStatistics(List<CertifiedProductSearchDetails> listings) {
        List<CertifiedProductSearchDetails> listingsWithSvap = listings.stream()
            .filter(item -> doesListingHaveSvap(item))
            .map(item -> item)
            .collect(Collectors.toList());

        List<SvapReportDeveloperCounts> counts = new ArrayList<SvapReportDeveloperCounts>();

        for (CertifiedProductSearchDetails listing : listingsWithSvap) {
            Optional<SvapReportDeveloperCounts> count = counts.stream()
                    .filter(item -> item.getDeveloperName().equals(listing.getDeveloper().getName())
                            && item.getAcb().equals(listing.getCertifyingBody().get(CertifiedProductSearchDetails.ACB_NAME_KEY).toString()))
                    .findAny();

            SvapReportDeveloperCounts countToUpdate;

            if (count.isPresent()) {
                countToUpdate = count.get();
            } else {
                countToUpdate = SvapReportDeveloperCounts.builder()
                        .acb(listing.getCertifyingBody().get(CertifiedProductSearchDetails.ACB_NAME_KEY).toString())
                        .certificationBodyId(Long.getLong(listing.getCertifyingBody().get(CertifiedProductSearchDetails.ACB_ID_KEY).toString()))
                        .developerId(listing.getDeveloper().getDeveloperId())
                        .developerName(listing.getDeveloper().getName())
                        .listingCount(0)
                        .criteriaCount(0)
                        .svapCount(0)
                        .build();
            }

            countToUpdate.setListingCount(countToUpdate.getListingCount() + 1);
            countToUpdate.setCriteriaCount(countToUpdate.getCriteriaCount() + getCriteriaWithSvapCount(listing));
            countToUpdate.setSvapCount(countToUpdate.getSvapCount() + getSvapCount(listing));
        }

        counts.forEach(srdc -> svapReportDeveloperCountsDao.create(srdc));
    }

    private Integer getSvapCount(CertifiedProductSearchDetails listing) {
        return listing.getCertificationResults().stream()
                .filter(cr -> cr.getSvaps() != null && cr.getSvaps().size() > 0)
                .collect(Collectors.summingInt(cr -> cr.getSvaps().size()));
    }

    private Integer getCriteriaWithSvapCount(CertifiedProductSearchDetails listing) {
        return listing.getCertificationResults().stream()
                .filter(cr -> cr.getSvaps() != null && cr.getSvaps().size() > 0)
                .collect(Collectors.counting())
                .intValue();
    }

    private Boolean doesListingHaveSvap(CertifiedProductSearchDetails listing) {
        return listing.getCertificationResults().stream()
            .anyMatch(cr -> cr.getSvaps() != null && cr.getSvaps().size() > 0);
    }

    private List<CertifiedProductSearchDetails> getAll2015Listings() {

        return getAll2015CertifiedProducts().parallelStream()
                .filter(l -> l.getId() == 10607L)
                .map(listing -> getCertifiedProductSearchDetails(listing.getId()))
                .collect(Collectors.toList());
    }

    private List<CertifiedProductDetailsDTO> getAll2015CertifiedProducts() {
        LOGGER.info("Retrieving all 2015 listings");
        List<CertifiedProductDetailsDTO> listings = certifiedProductDAO.findByEdition(
                CertificationEditionConcept.CERTIFICATION_EDITION_2015.getYear());
        LOGGER.info("Completed retreiving all 2015 listings");
        return listings;
    }

    private CertifiedProductSearchDetails getCertifiedProductSearchDetails(Long certifiedProductId) {
        try {
            long start = (new Date()).getTime();
            CertifiedProductSearchDetails listing = certifiedProductDetailsManager.getCertifiedProductDetails(certifiedProductId);
            LOGGER.info("Completed details for listing(" + ((new Date()).getTime() - start) + "ms): " + certifiedProductId);
            return listing;
        } catch (EntityRetrievalException e) {
            LOGGER.error("Could not retrieve details for listing id: " + certifiedProductId);
            LOGGER.catching(e);
            return null;
        }
    }

}
