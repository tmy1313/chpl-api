package gov.healthit.chpl.surveillance.report;

import java.util.List;
import java.util.stream.Collectors;

import javax.persistence.Query;

import org.apache.commons.collections.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import gov.healthit.chpl.compliance.surveillance.entity.SurveillanceEntity;
import gov.healthit.chpl.dao.impl.BaseDAOImpl;
import gov.healthit.chpl.entity.listing.CertifiedProductDetailsEntity;
import gov.healthit.chpl.exception.EntityCreationException;
import gov.healthit.chpl.exception.EntityRetrievalException;
import gov.healthit.chpl.surveillance.report.domain.QuarterlyReport;
import gov.healthit.chpl.surveillance.report.domain.RelevantListing;
import gov.healthit.chpl.surveillance.report.entity.ListingWithPrivilegedSurveillanceEntity;
import gov.healthit.chpl.surveillance.report.entity.QuarterlyReportEntity;
import gov.healthit.chpl.util.AuthUtil;

@Repository("quarterlyReportDao")
public class QuarterlyReportDAO extends BaseDAOImpl {
    private static final String QUARTERLY_REPORT_HQL = "SELECT qr "
            + " FROM QuarterlyReportEntity qr "
            + " JOIN FETCH qr.quarter quarter "
            + " JOIN FETCH qr.acb acb "
            + " LEFT JOIN FETCH acb.address "
            + " WHERE qr.deleted = false ";

    private QuarterDAO quarterDao;

    @Autowired
    public QuarterlyReportDAO(QuarterDAO quarterDao) {
        this.quarterDao = quarterDao;
    }

    public QuarterlyReport getByQuarterAndAcbAndYear(Long quarterId, Long acbId, Integer year) {
        String queryStr = QUARTERLY_REPORT_HQL
                + " AND qr.year = :year "
                + " AND acb.id = :acbId "
                + " AND quarter.id = :quarterId";
        Query query = entityManager.createQuery(queryStr);
        query.setParameter("quarterId", quarterId);
        query.setParameter("year", year);
        query.setParameter("acbId", acbId);
        List<QuarterlyReportEntity> entityResults = query.getResultList();
        if (CollectionUtils.isEmpty(entityResults)) {
            return null;
        }
        return entityResults.get(0).toDomain();
    }

    public List<QuarterlyReport> getByAcbAndYear(Long acbId, Integer year) {
        String queryStr = QUARTERLY_REPORT_HQL
                + " AND qr.year = :year "
                + " AND acb.id = :acbId";
        Query query = entityManager.createQuery(queryStr);
        query.setParameter("year", year);
        query.setParameter("acbId", acbId);
        List<QuarterlyReportEntity> entityResults = query.getResultList();
        return entityResults.stream()
            .map(entity -> entity.toDomain())
            .collect(Collectors.toList());
    }

    public List<QuarterlyReport> getByAcb(Long acbId) {
        String queryStr = QUARTERLY_REPORT_HQL
                + " AND acb.id = :acbId";
        Query query = entityManager.createQuery(queryStr);
        query.setParameter("acbId", acbId);
        List<QuarterlyReportEntity> entityResults = query.getResultList();
        return entityResults.stream()
                .map(entity -> entity.toDomain())
                .collect(Collectors.toList());
    }

    public List<QuarterlyReport> getAll() {
        Query query = entityManager.createQuery(QUARTERLY_REPORT_HQL);
        List<QuarterlyReportEntity> entityResults = query.getResultList();
        return entityResults.stream()
                .map(entity -> entity.toDomain())
                .collect(Collectors.toList());
    }

    public QuarterlyReport getById(Long id) throws EntityRetrievalException {
        QuarterlyReportEntity entity = getEntityById(id);
        if (entity != null) {
            return entity.toDomain();
        }
        return null;
    }

    public boolean isListingRelevant(Long acbId, Long listingId) {
        String queryStr = "SELECT DISTINCT cp "
                + "FROM CertifiedProductEntity cp "
                + "WHERE cp.id = :listingId "
                + "AND cp.certificationBodyId = :acbId ";
        Query query = entityManager.createQuery(queryStr);
        query.setParameter("listingId", listingId);
        query.setParameter("acbId", acbId);
        List<CertifiedProductDetailsEntity> entities = query.getResultList();
        return entities != null && entities.size() > 0;
    }

    /**
     * Returns true if the surveillance specified is related to a listing on the
     * ACB that's relevant to the quarterly report
     * and was open during the reporting period; false otherwise.
     */
    public boolean isSurveillanceRelevant(QuarterlyReport quarterlyReport, Long survId) {
        String queryStr = "SELECT surv "
                + "FROM SurveillanceEntity surv "
                + "JOIN FETCH surv.certifiedProduct listing "
                + "WHERE surv.id = :survId "
                + "AND listing.certificationBodyId = :acbId "
                + "AND surv.startDate <= :endDate "
                + "AND (surv.endDate IS NULL OR surv.endDate >= :startDate)";
        Query query = entityManager.createQuery(queryStr);
        query.setParameter("survId", survId);
        query.setParameter("acbId", quarterlyReport.getAcb().getId());
        query.setParameter("startDate", quarterlyReport.getStartDay());
        query.setParameter("endDate", quarterlyReport.getEndDay());
        List<SurveillanceEntity> entities = query.getResultList();
        return entities != null && entities.size() > 0;
    }

    /**
     * Returns listings with at least one surveillance that was in an open state during a time interval.
     */
    @Transactional(readOnly = true)
    public List<RelevantListing> getListingsWithRelevantSurveillance(QuarterlyReport quarterlyReport) {
        String queryStr = "SELECT DISTINCT listing "
                + "FROM ListingWithPrivilegedSurveillanceEntity listing "
                + "JOIN FETCH listing.surveillances surv "
                + "LEFT JOIN FETCH surv.surveillanceType "
                + "WHERE listing.certificationBodyId = :acbId "
                + "AND listing.deleted = false "
                + "AND surv.startDate <= :endDate "
                + "AND (surv.endDate IS NULL OR surv.endDate >= :startDate)";
        Query query = entityManager.createQuery(queryStr);
        query.setParameter("acbId", quarterlyReport.getAcb().getId());
        query.setParameter("startDate", quarterlyReport.getStartDay());
        query.setParameter("endDate", quarterlyReport.getEndDay());

        List<ListingWithPrivilegedSurveillanceEntity> listingsWithSurvEntities = query.getResultList();
        return listingsWithSurvEntities.stream()
                .map(entity -> entity.toDomain())
                .collect(Collectors.toList());
    }

    /**
     * Returns a relevant listing object if the listing is relevant during the dates specified.
     * Otherwise returns null.
     */
    public RelevantListing getRelevantListing(Long listingId, QuarterlyReport quarterlyReport) {
        String queryStr = "SELECT DISTINCT listing "
                + "FROM ListingWithPrivilegedSurveillanceEntity listing "
                + "LEFT JOIN FETCH listing.surveillances surv "
                + "LEFT JOIN FETCH surv.surveillanceType "
                + "WHERE listing.id = :listingId "
                + "AND listing.deleted = false "
                + "AND listing.certificationBodyId = :acbId ";
        Query query = entityManager.createQuery(queryStr);
        query.setParameter("listingId", listingId);
        query.setParameter("acbId", quarterlyReport.getAcb().getId());
        List<ListingWithPrivilegedSurveillanceEntity> entities = query.getResultList();
        if (CollectionUtils.isEmpty(entities)) {
            return null;
        }
        return entities.get(0).toDomain();
    }

    /**
     * Returns listings owned by the ACB
     */
    @Transactional(readOnly = true)
    public List<RelevantListing> getRelevantListings(QuarterlyReport quarterlyReport) {
        String queryStr = "SELECT DISTINCT listing "
                + "FROM ListingWithPrivilegedSurveillanceEntity listing "
                + "LEFT JOIN FETCH listing.surveillances surv "
                + "LEFT JOIN FETCH surv.surveillanceType "
                + "WHERE listing.certificationBodyId = :acbId "
                + "AND listing.deleted = false ";
        Query query = entityManager.createQuery(queryStr);
        query.setParameter("acbId", quarterlyReport.getAcb().getId());

        List<ListingWithPrivilegedSurveillanceEntity> entities = query.getResultList();
        return entities.stream()
                .map(entity -> entity.toDomain())
                .collect(Collectors.toList());
    }

    public Long create(QuarterlyReport toCreate) throws EntityCreationException {
        if (toCreate.getAcb() == null || toCreate.getAcb().getId() == null) {
            throw new EntityCreationException("An ACB must be provided in order to create a quarterly report.");
        }
        if (toCreate.getYear() == null) {
            throw new EntityCreationException("A year must be provided in order to create a quarterly report.");
        }
        if (toCreate.getQuarter() == null) {
            throw new EntityCreationException("A quarter must be provided in order to create a quarterly report.");
        }
        QuarterlyReportEntity toCreateEntity = QuarterlyReportEntity.builder()
                .certificationBodyId(toCreate.getAcb().getId())
                .year(toCreate.getYear())
                .prioritizedElementSummary(toCreate.getPrioritizedElementSummary())
                .quarterId(quarterDao.getByName(toCreate.getQuarter()).getId())
                .activitiesOutcomesSummary(toCreate.getSurveillanceActivitiesAndOutcomes())
                .reactiveSurveillanceSummary(toCreate.getReactiveSurveillanceSummary())
                .disclosureRequirementsSummary(toCreate.getDisclosureRequirementsSummary())
                .build();

        super.create(toCreateEntity);
        toCreate.setId(toCreateEntity.getId());
        return toCreateEntity.getId();
    }

    public void update(QuarterlyReport toUpdate) throws EntityRetrievalException {
        QuarterlyReportEntity toUpdateEntity = getEntityById(toUpdate.getId());
        toUpdateEntity.setActivitiesOutcomesSummary(toUpdate.getSurveillanceActivitiesAndOutcomes());
        toUpdateEntity.setPrioritizedElementSummary(toUpdate.getPrioritizedElementSummary());
        toUpdateEntity.setReactiveSurveillanceSummary(toUpdate.getReactiveSurveillanceSummary());
        toUpdateEntity.setDisclosureRequirementsSummary(toUpdate.getDisclosureRequirementsSummary());
        toUpdateEntity.setLastModifiedUser(AuthUtil.getAuditId());

        super.update(toUpdateEntity);
    }

    public void delete(Long idToDelete) throws EntityRetrievalException {
        QuarterlyReportEntity toDeleteEntity = getEntityById(idToDelete);
        toDeleteEntity.setDeleted(true);
        super.update(toDeleteEntity);
    }

    private QuarterlyReportEntity getEntityById(Long id) throws EntityRetrievalException {
        String queryStr = QUARTERLY_REPORT_HQL
                + " AND qr.id = :id";
        Query query = entityManager.createQuery(queryStr);
        query.setParameter("id", id);
        List<QuarterlyReportEntity> results = query.getResultList();
        if (results == null || results.size() == 0) {
            throw new EntityRetrievalException("No quarterly report with ID " + id + " exists.");
        }
        return results.get(0);
    }
}
