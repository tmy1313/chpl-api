package gov.healthit.chpl.scheduler.job.onetime.measures;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.persistence.Query;

import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.stereotype.Component;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallbackWithoutResult;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import gov.healthit.chpl.auth.user.User;
import gov.healthit.chpl.dao.impl.BaseDAOImpl;
import gov.healthit.chpl.domain.CertificationCriterion;
import gov.healthit.chpl.domain.Measure;
import gov.healthit.chpl.domain.MeasureDomain;
import gov.healthit.chpl.entity.MacraMeasureEntity;
import gov.healthit.chpl.exception.EntityRetrievalException;
import gov.healthit.chpl.exception.ObjectNotFoundException;
import gov.healthit.chpl.listing.measure.LegacyMacraMeasureCriterionMapEntity;
import gov.healthit.chpl.listing.measure.MeasureCriterionMapEntity;
import gov.healthit.chpl.listing.measure.MeasureDAO;
import gov.healthit.chpl.listing.measure.MeasureDomainEntity;
import gov.healthit.chpl.listing.measure.MeasureEntity;
import gov.healthit.chpl.scheduler.job.QuartzJob;
import gov.healthit.chpl.service.CertificationCriterionService;
import lombok.extern.log4j.Log4j2;
import net.sf.ehcache.CacheManager;

@Log4j2(topic = "updateMeasuresJobLogger")
public class UpdateMeasuresJob extends QuartzJob {

    @Autowired
    private UpdateMeasuresJobDAO updateMeasuresJobDAO;


    @Autowired
    private CertificationCriterionService certificationCriterionService;

    @Autowired
    private JpaTransactionManager txManager;

    //Format: domain|measure
    private static final String[] MEASURES_TO_REMOVE = {
            "EH/CAH Medicare and Medicaid PI|Electronic Prescribing: Eligible Hospital/Critical Access Hospital",
            "EP Medicaid PI|Electronic Prescribing: Eligible Professional",
            "EH/CAH Medicaid PI|Computerized Provider Order Entry - Medications: Eligible Hospital/Critical Access Hospital",
            "EP Medicaid PI|Computerized Provider Order Entry - Medications: Eligible Professional",
            "EH/CAH Medicaid PI|Computerized Provider Order Entry - Laboratory: Eligible Hospital/Critical Access Hospital",
            "EP Medicaid PI|Computerized Provider Order Entry - Laboratory: Eligible Professional",
            "EH/CAH Medicaid PI|Computerized Provider Order Entry - Diagnostic Imaging: Eligible Hospital/Critical Access Hospital",
            "EP Medicaid PI|Computerized Provider Order Entry - Diagnostic Imaging: Eligible Professional",
            "EH/CAH Medicare and Medicaid PI|Provide Patients Electronic Access to Their Health Information (formerly Patient Electronic Access): Eligible Hospital/Critical Access Hospital",
            "EP Medicaid PI|Patient Electronic Access: Eligible Professional",
            "EH/CAH Medicaid PI|Patient-Specific Education: Eligible Hospital/Critical Access Hospital",
            "EP Medicaid PI|Patient-Specific Education: Eligible Professional",
            "EH/CAH Medicaid PI|View, Download, or Transmit (VDT): Eligible Hospital/Critical Access Hospital",
            "EP Medicaid PI|View, Download, or Transmit (VDT): Eligible Professional",
            "EH/CAH Medicaid PI|Secure Electronic Messaging: Eligible Hospital/Critical Access Hospital",
            "EP Medicaid PI|Secure Electronic Messaging: Eligible Professional",
            "EH/CAH Medicaid PI|Patient-Generated Health Data: Eligible Hospital/Critical Access Hospital",
            "EP Medicaid PI|Patient-Generated Health Data: Eligible Professional",
            "EH/CAH Medicare and Medicaid PI|Support Electronic Referral Loops by Sending Health Information (formerly Patient Care Record Exchange):  Eligible Hospital/Critical Access Hospital",
            "EP Medicaid PI|Patient Care Record Exchange: Eligible Professional",
            "EH/CAH Medicaid PI|Request/Accept Patient Care Record: Eligible Hospital/Critical Access Hospital",
            "EP Medicaid PI|Request/Accept Patient Care Record: Eligible Professional",
            "EH/CAH Medicaid PI|Medication/Clinical Information Reconciliation: Eligible Hospital/Critical Access Hospital",
            "EP Medicaid PI|Medication/Clinical Information Reconciliation: Eligible Professional"};

    public UpdateMeasuresJob() throws Exception {
        super();
    }

    @Override
    public void execute(JobExecutionContext jobContext) throws JobExecutionException {
        SpringBeanAutowiringSupport.processInjectionBasedOnCurrentContext(this);
        LOGGER.info("********* Starting the Remove Criteria job. *********");
        // We need to manually create a transaction in this case because of how AOP works. When a method is
        // annotated with @Transactional, the transaction wrapper is only added if the object's proxy is called.
        // The object's proxy is not called when the method is called from within this class. The object's proxy
        // is called when the method is public and is called from a different object.
        // https://stackoverflow.com/questions/3037006/starting-new-transaction-in-spring-bean
        TransactionTemplate txTemplate = new TransactionTemplate(txManager);
        txTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        txTemplate.execute(new TransactionCallbackWithoutResult() {

            @Override
            protected void doInTransactionWithoutResult(TransactionStatus status) {
                try {
                    getMeasuresToRemove().stream()
                            .forEach(measure -> {
                                Measure m = removeMeasure(measure);
                                LOGGER.always().log(String.format("%s    |     %s     |     %s     -- Has been removed", m.getId(), m.getDomain().getName(), m.getName()));
                            });

                    createLegacyMacraMeasureToMeasureMaps();
                    CacheManager.getInstance().clearAll();
                } catch (final Exception ex) {
                    LOGGER.error("Exception updating measures.", ex);
                    status.setRollbackOnly();
                }
            }
        });

        LOGGER.info("********* Completed the Remove Criteria job. *********");
    }

    private Measure removeMeasure(Measure measure) {
        measure.setRemoved(true);
        return updateMeasuresJobDAO.updateMeasure(measure);
    }

    private List<Measure> getMeasuresToRemove() {
        Set<Measure> allMeasures = updateMeasuresJobDAO.findAllMeasures();
        List<Measure> ms = Stream.of(MEASURES_TO_REMOVE)
                .map(str -> getMeasureFromString(str, allMeasures))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toList());

        LOGGER.always().log(String.format("Found %s measure for removal.", ms.size()));

        return ms;
    }

    private Optional<Measure> getMeasureFromString(String measureString, Set<Measure> measures) {
        String[] measureParts = measureString.split("\\|");
        return measures.stream()
                .filter(m -> m.getDomain().getName().equals(measureParts[0])
                        && m.getName().equals(measureParts[1]))
                .findAny();
    }

    private void createLegacyMacraMeasureToMeasureMaps() throws EntityRetrievalException, ObjectNotFoundException {
        List<Measure> measures = createMeasures();
        List<MacraMeasureEntity> legacyMeasures = createLegacyMeasures();

        for (MacraMeasureEntity legacy : legacyMeasures) {

            Optional<MeasureCriterionMapEntity> measureCriterionMap = getAllowedMeasureBasedOnLegacyMacraMeasure(legacy, measures);
            if (!measureCriterionMap.isPresent()) {
                throw new ObjectNotFoundException(String.format("Could not locate MeasureCriteriaMap for: %s", legacy.toString()));
            }

            createLegacyMacraMeasureCriteria(legacy.getId(), measureCriterionMap.get().getId());
            LOGGER.always().log(String.format("Inserted Mapping - Leagcy: %s  AllowedMeasure: %s", legacy.getId(), measureCriterionMap.get().getId()));
        }

    }

    private LegacyMacraMeasureCriterionMapEntity createLegacyMacraMeasureCriteria(Long legacyMacraMeasureId, Long measureCriterionId) {
        LegacyMacraMeasureCriterionMapEntity entity = new LegacyMacraMeasureCriterionMapEntity();
        entity.setLegacyMacraMeasureId(legacyMacraMeasureId);
        entity.setMeasureCriterionId(measureCriterionId);
        entity.setLastModifiedUser(User.SYSTEM_USER_ID);
        entity.setDeleted(false);
        return updateMeasuresJobDAO.createLegacyMacraMeasureCriterionMap(entity);
    }

    private Optional<MeasureCriterionMapEntity> getAllowedMeasureBasedOnLegacyMacraMeasure(MacraMeasureEntity legacy, List<Measure> measures) {
        return measures.stream()
                .map(measure -> updateMeasuresJobDAO.getMeasureEntity(measure.getId()))
                .filter(entity -> legacy.getName().equals(entity.getName())
                        && legacy.getDescription().equals(entity.getRequiredTest()))
                .flatMap(measure -> measure.getAllowedCriteria().stream())
                .filter(criterion -> criterion.getCriterion().getId().equals(legacy.getCertificationCriterion().getId()))
                .findAny();
    }

    private List<Measure> createMeasures() throws EntityRetrievalException {
        return new ArrayList<Measure>(Arrays.asList(
                createMeasure("EH/CAH Medicare PI",
                        "RT7",
                        "Required Test 7: Medicare Promoting Interoperability Programs",
                        "Support Electronic Referral Loops by Sending Health Information (formerly Patient Care Record Exchange): Eligible Hospital/Critical Access Hospital",
                        false,
                        new ArrayList<CertificationCriterion>(Arrays.asList(
                                certificationCriterionService.get(CertificationCriterionService.Criteria2015.B_1_CURES),
                                certificationCriterionService.get(CertificationCriterionService.Criteria2015.B_1_OLD)))),
                createMeasure("EH/CAH Medicare PI",
                        "RT1",
                        "Required Test 1: Medicare Promoting Interoperability Programs",
                        "Electronic Prescribing: Eligible Hospital/Critical Access Hospital",
                        false,
                        new ArrayList<CertificationCriterion>(Arrays.asList(
                                certificationCriterionService.get(CertificationCriterionService.Criteria2015.B_3_CURES),
                                certificationCriterionService.get(CertificationCriterionService.Criteria2015.B_3_OLD)))),
                createMeasure("EH/CAH Medicare PI",
                        "RT2",
                        "Required Test 2: Medicare Promoting Interoperability Programs",
                        "Provide Patients Electronic Access to Their Health Information (formerly Patient Electronic Access): Eligible Hospital/Critical Access Hospital",
                        true,
                        new ArrayList<CertificationCriterion>(Arrays.asList(
                                certificationCriterionService.get(CertificationCriterionService.Criteria2015.E_1_CURES),
                                certificationCriterionService.get(CertificationCriterionService.Criteria2015.E_1_OLD),
                                certificationCriterionService.get(CertificationCriterionService.Criteria2015.G_8),
                                certificationCriterionService.get(CertificationCriterionService.Criteria2015.G_9_CURES),
                                certificationCriterionService.get(CertificationCriterionService.Criteria2015.G_9_OLD),
                                certificationCriterionService.get(CertificationCriterionService.Criteria2015.G_10)))),
                createMeasure("EH/CAH Medicare PI",
                        "RT2",
                        "Required Test 2: Medicare Promoting Interoperability Programs",
                        "Provide Patients Electronic Access to Their Health Information (formerly Patient Electronic Access): Eligible Clinician",
                        true,
                        new ArrayList<CertificationCriterion>(Arrays.asList(
                                certificationCriterionService.get(CertificationCriterionService.Criteria2015.G_10))))
                ));
    }

    private Measure createMeasure(String domain, String abbr, String requiredTest, String name, Boolean criteriaSelectionReqd, List<CertificationCriterion> criteria) throws EntityRetrievalException {
        Measure measure = Measure.builder()
                .domain(updateMeasuresJobDAO.findMeasureDomainByDomain(domain))
                .abbreviation(abbr)
                .requiredTest(requiredTest)
                .name(name)
                .requiresCriteriaSelection(criteriaSelectionReqd)
                .removed(false)
                .build();
        final Measure savedMeasure = updateMeasuresJobDAO.createMeasure(measure);
        LOGGER.always().log(String.format("Inserted Measure: %s", savedMeasure.toString()));

        criteria.stream()
                .forEach(criterion -> {
                    MeasureCriterionMapEntity e = updateMeasuresJobDAO.createMeasureCrierionMap(criterion.getId(), savedMeasure.getId(), User.SYSTEM_USER_ID);
                    LOGGER.always().log(String.format("     Inserted Allowed Measure Criteria: %s", e.toString()));
                });

        return savedMeasure;
    }


    private List<MacraMeasureEntity> createLegacyMeasures() {
        return new ArrayList<MacraMeasureEntity>(Arrays.asList(
                createLegacyMeasure(certificationCriterionService.get(CertificationCriterionService.Criteria2015.B_1_CURES).getId(),
                        "RT7 EH/CAH Medicare PI",
                        "Support Electronic Referral Loops by Sending Health Information (formerly Patient Care Record Exchange): Eligible Hospital/Critical Access Hospital",
                        "Required Test 7: Medicare Promoting Interoperability Programs"),
                createLegacyMeasure(certificationCriterionService.get(CertificationCriterionService.Criteria2015.B_1_OLD).getId(),
                        "RT7 EH/CAH Medicare PI",
                        "Support Electronic Referral Loops by Sending Health Information (formerly Patient Care Record Exchange): Eligible Hospital/Critical Access Hospital",
                        "Required Test 7: Medicare Promoting Interoperability Programs"),
                createLegacyMeasure(certificationCriterionService.get(CertificationCriterionService.Criteria2015.B_3_CURES).getId(),
                        "RT1 EH/CAH Medicare PI",
                        "Electronic Prescribing: Eligible Hospital/Critical Access Hospital",
                        "Required Test 1: Medicare Promoting Interoperability Programs"),
                createLegacyMeasure(certificationCriterionService.get(CertificationCriterionService.Criteria2015.B_3_OLD).getId(),
                        "RT1 EH/CAH Medicare PI",
                        "Electronic Prescribing: Eligible Hospital/Critical Access Hospital",
                        "Required Test 1: Medicare Promoting Interoperability Programs"),
                createLegacyMeasure(certificationCriterionService.get(CertificationCriterionService.Criteria2015.E_1_CURES).getId(),
                        "RT2a EH/CAH Medicare PI",
                        "Provide Patients Electronic Access to Their Health Information (formerly Patient Electronic Access): Eligible Hospital/Critical Access Hospital",
                        "Required Test 2: Medicare Promoting Interoperability Programs"),
                createLegacyMeasure(certificationCriterionService.get(CertificationCriterionService.Criteria2015.E_1_OLD).getId(),
                        "RT2a EH/CAH Medicare PI",
                        "Provide Patients Electronic Access to Their Health Information (formerly Patient Electronic Access): Eligible Hospital/Critical Access Hospital",
                        "Required Test 2: Medicare Promoting Interoperability Programs"),
                createLegacyMeasure(certificationCriterionService.get(CertificationCriterionService.Criteria2015.E_1_CURES).getId(),
                        "RT2b EH/CAH Medicare PI",
                        "Provide Patients Electronic Access to Their Health Information (formerly Patient Electronic Access): Eligible Hospital/Critical Access Hospital",
                        "Required Test 2: Medicare Promoting Interoperability Programs"),
                createLegacyMeasure(certificationCriterionService.get(CertificationCriterionService.Criteria2015.E_1_OLD).getId(),
                        "RT2b EH/CAH Medicare PI",
                        "Provide Patients Electronic Access to Their Health Information (formerly Patient Electronic Access): Eligible Hospital/Critical Access Hospital",
                        "Required Test 2: Medicare Promoting Interoperability Programs"),
                createLegacyMeasure(certificationCriterionService.get(CertificationCriterionService.Criteria2015.G_8).getId(),
                        "RT2a EH/CAH Medicare PI",
                        "Provide Patients Electronic Access to Their Health Information (formerly Patient Electronic Access): Eligible Hospital/Critical Access Hospital",
                        "Required Test 2: Medicare Promoting Interoperability Programs"),
                createLegacyMeasure(certificationCriterionService.get(CertificationCriterionService.Criteria2015.G_8).getId(),
                        "RT2c EH/CAH Medicare PI",
                        "Provide Patients Electronic Access to Their Health Information (formerly Patient Electronic Access): Eligible Hospital/Critical Access Hospital",
                        "Required Test 2: Medicare Promoting Interoperability Programs"),
                createLegacyMeasure(certificationCriterionService.get(CertificationCriterionService.Criteria2015.G_9_CURES).getId(),
                        "RT2a EH/CAH Medicare PI",
                        "Provide Patients Electronic Access to Their Health Information (formerly Patient Electronic Access): Eligible Hospital/Critical Access Hospital",
                        "Required Test 2: Medicare Promoting Interoperability Programs"),
                createLegacyMeasure(certificationCriterionService.get(CertificationCriterionService.Criteria2015.G_9_OLD).getId(),
                        "RT2a EH/CAH Medicare PI",
                        "Provide Patients Electronic Access to Their Health Information (formerly Patient Electronic Access): Eligible Hospital/Critical Access Hospital",
                        "Required Test 2: Medicare Promoting Interoperability Programs"),
                createLegacyMeasure(certificationCriterionService.get(CertificationCriterionService.Criteria2015.G_9_CURES).getId(),
                        "RT2c EH/CAH Medicare PI",
                        "Provide Patients Electronic Access to Their Health Information (formerly Patient Electronic Access): Eligible Hospital/Critical Access Hospital",
                        "Required Test 2: Medicare Promoting Interoperability Programs"),
                createLegacyMeasure(certificationCriterionService.get(CertificationCriterionService.Criteria2015.G_9_OLD).getId(),
                        "RT2c EH/CAH Medicare PI",
                        "Provide Patients Electronic Access to Their Health Information (formerly Patient Electronic Access): Eligible Hospital/Critical Access Hospital",
                        "Required Test 2: Medicare Promoting Interoperability Programs"),
                createLegacyMeasure(certificationCriterionService.get(CertificationCriterionService.Criteria2015.G_10).getId(),
                        "RT2a EH/CAH Medicare PI",
                        "Provide Patients Electronic Access to Their Health Information (formerly Patient Electronic Access): Eligible Clinician",
                        "Required Test 2: Medicare Promoting Interoperability Programs"),
                createLegacyMeasure(certificationCriterionService.get(CertificationCriterionService.Criteria2015.G_10).getId(),
                        "RT2c EH/CAH Medicare PI",
                        "Provide Patients Electronic Access to Their Health Information (formerly Patient Electronic Access): Eligible Hospital/Critical Access Hospital",
                        "Required Test 2: Medicare Promoting Interoperability Programs")
                ));
    }

    private MacraMeasureEntity createLegacyMeasure(Long criterionId, String value, String name, String description) {
        MacraMeasureEntity entity = new MacraMeasureEntity();
        entity.setCertificationCriterionId(criterionId);
        entity.setValue(value);
        entity.setName(name);
        entity.setDescription(description);
        entity.setRemoved(false);
        entity.setLastModifiedUser(User.SYSTEM_USER_ID);
        entity.setDeleted(false);

        MacraMeasureEntity e = updateMeasuresJobDAO.createMacraMeasure(entity);
        LOGGER.always().log(String.format("Inserted Legacy Macra Measure: %s", e.toString()));
        return e;
    }

    @Component
    private static class UpdateMeasuresJobDAO extends BaseDAOImpl {
        @Autowired
        private MeasureDAO measureDAO;

        public MacraMeasureEntity createMacraMeasure(MacraMeasureEntity entity) {
            super.create(entity);
            return getMacraMeasureById(entity.getId());
        }

        private MacraMeasureEntity getMacraMeasureById(Long id) {
            Query query = entityManager.createQuery(
                    "SELECT mme "
                    + "FROM MacraMeasureEntity mme "
                    + "LEFT OUTER JOIN FETCH mme.certificationCriterion cce "
                    + "LEFT OUTER JOIN FETCH cce.certificationEdition "
                    + "WHERE (NOT mme.deleted = true) "
                    + "AND mme.id = :id ",
                    MacraMeasureEntity.class);
            query.setParameter("id", id);
            List<MacraMeasureEntity> result = query.getResultList();
            if (result == null || result.size() == 0) {
                return null;
            }
            return result.get(0);
        }

        public MeasureDomain findMeasureDomainByDomain(String domain) throws EntityRetrievalException {
            MeasureDomainEntity entity = getMeasureDomainByDomain(domain);
            if (entity != null) {
                return entity.convert();
            } else {
                return null;
            }
        }

        private MeasureDomainEntity getMeasureDomainByDomain(String domain) throws EntityRetrievalException {
            Query query = entityManager.createQuery(
                    "SELECT md "
                    + "FROM MeasureDomainEntity md "
                    + "WHERE md.deleted = false "
                    + "AND md.domain = :domain ",
                    MeasureDomainEntity.class);
            query.setParameter("domain", domain);
            List<MeasureDomainEntity> entities = query.getResultList();

            if (entities != null && entities.size() > 0) {
                return entities.get(0);
            } else {
                throw new EntityRetrievalException(String.format("Could not locate measure domain: %s", domain));
            }

        }

        public Measure updateMeasure(Measure measure) {
            MeasureEntity result = getMeasureEntity(measure.getId());
            result.setAbbreviation(measure.getAbbreviation());
            result.setName(measure.getName());
            result.setRemoved(measure.getRemoved());

            update(result);

            return measureDAO.getById(result.getId());
        }

        public Measure createMeasure(Measure measure) {
            MeasureEntity entity = new MeasureEntity();
            entity.setDomain(MeasureDomainEntity.builder().id(measure.getDomain().getId()).build());
            entity.setAbbreviation(measure.getAbbreviation());
            entity.setRequiredTest(measure.getRequiredTest());
            entity.setName(measure.getName());
            entity.setCriteriaSelectionRequired(measure.getRequiresCriteriaSelection());
            entity.setRemoved(measure.getRemoved());
            entity.setLastModifiedUser(User.SYSTEM_USER_ID);
            entity.setDeleted(false);
            super.create(entity);
            return measureDAO.getById(entity.getId());
        }

        public MeasureEntity getMeasureEntity(Long id) {
            Query query = entityManager.createQuery(
                    MeasureDAO.MEASURE_HQL_BEGIN
                    + "WHERE measure.deleted = false "
                    + "AND measure.id = :id ",
                    MeasureEntity.class);
            query.setParameter("id", id);
            List<MeasureEntity> entities = query.getResultList();

            MeasureEntity result = null;
            if (entities != null && entities.size() > 0) {
                result = entities.get(0);
            }
            return result;
        }

        public Set<Measure> findAllMeasures() {
            return measureDAO.findAll();
        }

        public MeasureCriterionMapEntity createMeasureCrierionMap(Long certificationCriterionId, Long measureId, Long lastUpdateUserId) {
            MeasureCriterionMapEntity entity = new MeasureCriterionMapEntity();
            entity.setCertificationCriterionId(certificationCriterionId);
            entity.setMeasureId(measureId);
            entity.setLastModifiedUser(lastUpdateUserId);
            entity.setDeleted(false);

            super.create(entity);

            return entity;
        }

        public LegacyMacraMeasureCriterionMapEntity createLegacyMacraMeasureCriterionMap(LegacyMacraMeasureCriterionMapEntity entity) {
            super.create(entity);
            return entity;
        }
    }
}