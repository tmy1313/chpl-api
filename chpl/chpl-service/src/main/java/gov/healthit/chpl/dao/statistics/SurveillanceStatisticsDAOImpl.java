package gov.healthit.chpl.dao.statistics;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.Query;

import org.springframework.stereotype.Repository;

import gov.healthit.chpl.dao.impl.BaseDAOImpl;
import gov.healthit.chpl.domain.DateRange;
import gov.healthit.chpl.domain.statistics.CertifiedBodyStatistics;
import gov.healthit.chpl.dto.NonconformityTypeStatisticsDTO;

@Repository("surveillanceStatisticsDAO")
public class SurveillanceStatisticsDAOImpl extends BaseDAOImpl implements SurveillanceStatisticsDAO {
    /**
     * Total # of Surveillance Activities.
     */
    @Override
    public Long getTotalSurveillanceActivities(final DateRange dateRange) {
        String hql = "SELECT count(*) " + "FROM SurveillanceEntity " + "WHERE ";
        if (dateRange == null) {
            hql += " deleted = false";
        } else {
            hql += "(deleted = false AND creationDate <= :endDate) " + " OR "
                    + "(deleted = true AND creationDate <= :endDate AND lastModifiedDate > :endDate) ";
        }

        Query query = entityManager.createQuery(hql);
        if (dateRange != null) {
            query.setParameter("endDate", dateRange.getEndDate());
        }
        return (Long) query.getSingleResult();
    }

    /**
     * Open Surveillance Activities.
     */
    @Override
    public Long getTotalOpenSurveillanceActivities(final DateRange dateRange) {
        String hql = "SELECT count(*) " + "FROM SurveillanceEntity " + "WHERE startDate <= now() "
                + "AND (endDate IS NULL OR endDate >= now()) ";
        if (dateRange == null) {
            hql += " AND deleted = false";
        } else {
            hql += "AND ((deleted = false AND creationDate <= :endDate) " + " OR "
                    + "(deleted = true AND creationDate <= :endDate AND lastModifiedDate > :endDate)) ";
        }

        Query query = entityManager.createQuery(hql);
        if (dateRange != null) {
            query.setParameter("endDate", dateRange.getEndDate());
        }
        return (Long) query.getSingleResult();
    }

    /**
     * Open Surveillance Activities By ACB.
     */
    @Override
    public List<CertifiedBodyStatistics> getTotalOpenSurveillanceActivitiesByAcb(final DateRange dateRange) {
        String hql = "SELECT cb.name, count(*) "
                + "FROM CertifiedProductEntity cp, "
                    + "CertificationBodyEntity cb, "
                    + "SurveillanceEntity s "
                + "WHERE s.startDate <= now() "
                + "AND (s.endDate IS NULL OR s.endDate >= now()) "
                + "AND cp.certificationBodyId = cb.id "
                + "AND cp.id = s.certifiedProductId ";

        if (dateRange == null) {
            hql += "AND s.deleted = false ";
        } else {
            hql += "AND ((s.deleted = false AND s.creationDate <= :endDate) " + " OR "
                    + "(s.deleted = true AND s.creationDate <= :endDate AND s.lastModifiedDate > :endDate)) ";
        }

        hql += "GROUP BY name ";
        hql += "ORDER BY cb.name ";

        Query query = entityManager.createQuery(hql);

        if (dateRange != null) {
            query.setParameter("endDate", dateRange.getEndDate());
        }

        List<Object[]> results = query.getResultList();
        List<CertifiedBodyStatistics> cbStats = new ArrayList<CertifiedBodyStatistics>();
        for (Object[] obj : results) {
            CertifiedBodyStatistics stat = new CertifiedBodyStatistics();
            stat.setName(obj[0].toString());
            stat.setYear(null);
            stat.setTotalListings(Long.valueOf(obj[1].toString()));
            stat.setCertificationStatusName(null);
            cbStats.add(stat);
        }
        return cbStats;

    }

    /**
     * Closed Surveillance Activities.
     */
    @Override
    public Long getTotalClosedSurveillanceActivities(final DateRange dateRange) {
        String hql = "SELECT count(*) " + "FROM SurveillanceEntity " + "WHERE startDate <= now() "
                + "AND (endDate IS NOT NULL AND endDate <= now()) ";
        if (dateRange == null) {
            hql += " AND deleted = false";
        } else {
            hql += "AND ((deleted = false AND creationDate <= :endDate) " + " OR "
                    + "(deleted = true AND creationDate <= :endDate AND lastModifiedDate > :endDate)) ";
        }

        Query query = entityManager.createQuery(hql);
        if (dateRange != null) {
            query.setParameter("endDate", dateRange.getEndDate());
        }
        return (Long) query.getSingleResult();
    }

    /**
     * Total # of NCs.
     */
    @Override
    public Long getTotalNonConformities(final DateRange dateRange) {
        String hql = "SELECT count(*) " + "FROM SurveillanceNonconformityEntity " + "WHERE ";
        if (dateRange == null) {
            hql += " deleted = false";
        } else {
            hql += "(deleted = false AND creationDate <= :endDate) " + " OR "
                    + "(deleted = true AND creationDate <= :endDate AND lastModifiedDate > :endDate) ";
        }

        Query query = entityManager.createQuery(hql);
        if (dateRange != null) {
            query.setParameter("endDate", dateRange.getEndDate());
        }
        return (Long) query.getSingleResult();
    }

    /**
     * Open NCs.
     */
    @Override
    public Long getTotalOpenNonconformities(final DateRange dateRange) {
        String hql = "SELECT count(*) " + "FROM SurveillanceNonconformityEntity " + "WHERE nonconformityStatusId = 1 ";
        if (dateRange == null) {
            hql += " AND deleted = false";
        } else {
            hql += " AND ((deleted = false AND creationDate <= :endDate) " + " OR "
                    + "(deleted = true AND creationDate <= :endDate AND lastModifiedDate > :endDate)) ";
        }

        Query query = entityManager.createQuery(hql);
        if (dateRange != null) {
            query.setParameter("endDate", dateRange.getEndDate());
        }
        return (Long) query.getSingleResult();
    }

    /**
     * Open NCs By ACB.
     */
    @Override
    public List<CertifiedBodyStatistics> getTotalOpenNonconformitiesByAcb(final DateRange dateRange) {
        String hql = "SELECT cb.name, count(*) "
                    + "FROM CertifiedProductEntity cp, "
                        + "CertificationBodyEntity cb, "
                        + "SurveillanceEntity s, "
                        + "SurveillanceRequirementEntity sr, "
                        + "SurveillanceNonconformityEntity sn "
                    + "WHERE sn.nonconformityStatusId = 1 "
                    + "AND cp.certificationBodyId = cb.id "
                    + "AND cp.id = s.certifiedProductId "
                    + "AND s.id = sr.surveillanceId "
                    + "AND sr.id = sn.surveillanceRequirementId ";

        if (dateRange == null) {
            hql += "AND sn.deleted = false ";
        } else {
            hql += "AND ((sn.deleted = false AND sn.creationDate <= :endDate) " + " OR "
                    + "(sn.deleted = true AND sn.creationDate <= :endDate AND sn.lastModifiedDate > :endDate)) ";
        }

        hql += "GROUP BY name ";
        hql += "ORDER BY cb.name ";

        Query query = entityManager.createQuery(hql);

        if (dateRange != null) {
            query.setParameter("endDate", dateRange.getEndDate());
        }

        List<Object[]> results = query.getResultList();
        List<CertifiedBodyStatistics> cbStats = new ArrayList<CertifiedBodyStatistics>();
        for (Object[] obj : results) {
            CertifiedBodyStatistics stat = new CertifiedBodyStatistics();
            stat.setName(obj[0].toString());
            stat.setYear(null);
            stat.setTotalListings(Long.valueOf(obj[1].toString()));
            stat.setCertificationStatusName(null);
            cbStats.add(stat);
        }
        return cbStats;
    }

    /**
     * Closed NCs.
     */
    @Override
    public Long getTotalClosedNonconformities(final DateRange dateRange) {
        String hql = "SELECT count(*) " + "FROM SurveillanceNonconformityEntity " + "WHERE nonconformityStatusId = 2 ";
        if (dateRange == null) {
            hql += " AND deleted = false";
        } else {
            hql += " AND ((deleted = false AND creationDate <= :endDate) " + " OR "
                    + "(deleted = true AND creationDate <= :endDate AND lastModifiedDate > :endDate)) ";
        }

        Query query = entityManager.createQuery(hql);
        if (dateRange != null) {
            query.setParameter("endDate", dateRange.getEndDate());
        }
        return (Long) query.getSingleResult();
    }

    @Override
    public List<NonconformityTypeStatisticsDTO> getAllNonconformitiesByCriterion() {
        String hql = "SELECT COUNT(type), type "
                + "FROM SurveillanceNonconformityEntity "
                + "WHERE deleted = false GROUP BY type";
        Query query = entityManager.createQuery(hql);

        List<Object[]> entities = query.getResultList();

        List<NonconformityTypeStatisticsDTO> dtos = new ArrayList<NonconformityTypeStatisticsDTO>();
        for (Object[] entity : entities) {
            NonconformityTypeStatisticsDTO dto = new NonconformityTypeStatisticsDTO();
            dto.setNonconformityCount(Long.valueOf(entity[0].toString()));
            dto.setNonconformityType(entity[1].toString());
            dtos.add(dto);
        }

        return dtos;
    }

}
