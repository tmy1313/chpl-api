package gov.healthit.chpl.dao.statistics;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Repository;

import gov.healthit.chpl.auth.user.User;
import gov.healthit.chpl.dao.impl.BaseDAOImpl;
import gov.healthit.chpl.entity.statistics.SvapReportDeveloperCountsEntity;
import gov.healthit.chpl.scheduler.job.svapreports.SvapReportDeveloperCounts;

@Repository("svapReportDeveloperCountsDAO")
public class SvapReportDeveloperCountsDAO extends BaseDAOImpl {
    public List<SvapReportDeveloperCounts> getAll() {
        return  getAllEntities().stream()
                .map(entity -> entity.toDomain())
                .collect(Collectors.toList());
    }

    public void create(SvapReportDeveloperCounts srdc) {
        create(SvapReportDeveloperCountsEntity.builder()
                .certificationBodyId(srdc.getCertificationBodyId())
                .developerId(srdc.getDeveloperId())
                .listingCount(srdc.getListingCount())
                .criteriaCount(srdc.getCriteriaCount())
                .svapCount(srdc.getSvapCount())
                .lastModifiedUser(User.SYSTEM_USER_ID)
                .build());
    }

    public void deleteAll(SvapReportDeveloperCounts srdc) {
        getAllEntities().forEach(entity -> {
            entity.setDeleted(true);
            update(entity);;
        });
    }

    private List<SvapReportDeveloperCountsEntity> getAllEntities() {
        String hql = "SELECT srdc.* "
                + "FROM SvapReportDeveloperCountsEntity srdc "
                + "JOIN JETCH srdc.developer "
                + "JOIN JETCH srdc.certificationBody "
                + "WHERE srdc.deleted = false ";

        return entityManager.createQuery(hql, SvapReportDeveloperCountsEntity.class)
                .getResultList();
    }

}
