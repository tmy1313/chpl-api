package gov.healthit.chpl.subscription.dao;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.persistence.Query;

import org.springframework.stereotype.Service;

import gov.healthit.chpl.auth.user.User;
import gov.healthit.chpl.dao.impl.BaseDAOImpl;
import gov.healthit.chpl.subscription.domain.SubscribedObjectType;
import gov.healthit.chpl.subscription.domain.Subscription;
import gov.healthit.chpl.subscription.domain.SubscriptionConsolidationMethod;
import gov.healthit.chpl.subscription.domain.SubscriptionReason;
import gov.healthit.chpl.subscription.domain.SubscriptionSubject;
import gov.healthit.chpl.subscription.entity.SubscribedObjectTypeEntity;
import gov.healthit.chpl.subscription.entity.SubscriptionConsolidationMethodEntity;
import gov.healthit.chpl.subscription.entity.SubscriptionEntity;
import gov.healthit.chpl.subscription.entity.SubscriptionReasonEntity;
import gov.healthit.chpl.subscription.entity.SubscriptionSubjectEntity;
import lombok.extern.log4j.Log4j2;

@Service
@Log4j2
public class SubscriptionDao extends BaseDAOImpl {
    private static final String SUBSCRIPTION_HQL = "SELECT subscription "
            + "FROM SubscriptionEntity subscription "
            + "LEFT JOIN FETCH subscription.subscriber subscriber "
            + "LEFT JOIN FETCH subscriber.subscriberStatus "
            + "LEFT JOIN FETCH subscription.subscriptionReason "
            + "LEFT JOIN FETCH subscription.subscriptionSubject subject "
            + "LEFT JOIN FETCH subject.subscribedObjectType "
            + "LEFT JOIN FETCH subscription.subscriptionConsolidationMethod ";

    public List<SubscriptionReason> getAllReasons() {
        Query query = entityManager.createQuery("SELECT reasons "
                + "FROM SubscriptionReasonEntity reasons "
                + "ORDER BY sortOrder",
                SubscriptionReasonEntity.class);

        List<SubscriptionReasonEntity> results = query.getResultList();
        return results.stream()
                .map(entity -> entity.toDomain())
                .toList();
    }

    public List<SubscribedObjectType> getAllSubscribedObjectTypes() {
        Query query = entityManager.createQuery("SELECT types "
                + "FROM SubscribedObjectTypeEntity types ",
                SubscribedObjectTypeEntity.class);

        List<SubscribedObjectTypeEntity> results = query.getResultList();
        return results.stream()
                .map(entity -> entity.toDomain())
                .toList();
    }

    //making this public because I suspect we will need it eventually for the management page
    public List<SubscriptionSubject> getAllSubjectsForObjectType(Long subscribedObjectTypeId) {
        Query query = entityManager.createQuery("SELECT subjects "
                + "FROM SubscriptionSubjectEntity subjects "
                + "WHERE subjects.subscribedObjectTypeId = :subscribedObjectTypeId",
                SubscriptionSubjectEntity.class);
        query.setParameter("subscribedObjectTypeId", subscribedObjectTypeId);

        List<SubscriptionSubjectEntity> results = query.getResultList();
        return results.stream()
                .map(entity -> entity.toDomain())
                .toList();
    }

    public void createSubscription(UUID subscriberId, Long subscribedObjectTypeId, Long subscribedObjectId, Long reasonId) {
        //Subscribing to a particular object may create create multiple subscriptions for each
        //"subject" related to that type of object. i.e. different things updated on a listing are different subjects.
        //A future management page might give a user more fine-grained control over the "subjects"
        //they subscribe to, so they could subscribe to surveillance added to a listing but not certification status changes.
        //For now, when you create a new subscription it will default to subscribing to all related subjects.
        List<SubscriptionSubject> subjectsForObjectType = getAllSubjectsForObjectType(subscribedObjectTypeId);
        Long dailyConsolidationMethodId = getSubscriptionConsolidationMethodId(SubscriptionConsolidationMethod.CONSOLIDATION_METHOD_DAILY);

        subjectsForObjectType.stream()
            .forEach(subject -> createSubscriptionIfNotExists(
                    subscriberId, subscribedObjectId, subject.getId(), dailyConsolidationMethodId, reasonId));
    }

    private void createSubscriptionIfNotExists(UUID subscriberId, Long subscribedObjectId, Long subjectId,
            Long consolidationMethodId, Long reasonId) {
        if (!doesSubscriptionExist(subscriberId, subscribedObjectId, subjectId)) {
            SubscriptionEntity subscriptionToCreate = new SubscriptionEntity();
            subscriptionToCreate.setLastModifiedUser(User.DEFAULT_USER_ID);
            subscriptionToCreate.setSubscribedObjectId(subscribedObjectId);
            subscriptionToCreate.setSubscriberId(subscriberId);
            subscriptionToCreate.setSubscriptionConsolidationMethodId(consolidationMethodId);
            subscriptionToCreate.setSubscriptionReasonId(reasonId);
            subscriptionToCreate.setSubscriptionSubjectId(subjectId);
            create(subscriptionToCreate);
        } else {
            LOGGER.info("A subscription for subscriber %s, subject ID %s, and object ID %s already exists"
                    + "and will not be created again.", subscriberId, subjectId, subscribedObjectId);
        }
    }

    private boolean doesSubscriptionExist(UUID subscriberId, Long subscribedObjectId, Long subjectId) {
        Query query = entityManager.createQuery("SELECT subscription "
                + "FROM SubscriptionEntity subscription "
                + "WHERE subscription.subscriberId = :subscriberId "
                + "AND subscription.subscribedObjectId = :subscribedObjectId "
                + "AND subscription.subscriptionSubjectId = :subscriptionSubjectId");
        query.setParameter("subscriberId", subscriberId);
        query.setParameter("subscribedObjectId", subscribedObjectId);
        query.setParameter("subscriptionSubjectId", subjectId);

        List<SubscriptionEntity> results = query.getResultList();
        return results != null && results.size() > 0;
    }

    public Subscription getSubscriptionById(Long subscriptionId) {
        Query query = entityManager.createQuery(SUBSCRIPTION_HQL
                + "WHERE susbscription.id = :subscriptionId",
                SubscriptionEntity.class);
        query.setParameter("subscriptionId", subscriptionId);

        List<SubscriptionEntity> results = query.getResultList();
        if (results == null || results.size() == 0) {
            return null;
        }
        return results.get(0).toDomain();
    }

    public List<Subscription> getSubscriptionsForSubscriber(UUID subscriberId) {
        Query query = entityManager.createQuery(SUBSCRIPTION_HQL
                + "WHERE subscriber.id = :subscriberId",
                SubscriptionEntity.class);
        query.setParameter("subscriberId", subscriberId);

        List<SubscriptionEntity> results = query.getResultList();
        return results.stream()
                .map(entity -> entity.toDomain())
                .collect(Collectors.toList());
    }

    private Long getSubscriptionConsolidationMethodId(String consolidationMethodName) {
        Query query = entityManager.createQuery("SELECT cm "
                + "FROM SubscriptionConsolidationMethodEntity cm "
                + "WHERE cm.name = :consolidationMethodName",
                SubscriptionConsolidationMethodEntity.class);
        query.setParameter("consolidationMethodName", consolidationMethodName);

        List<SubscriptionConsolidationMethodEntity> results = query.getResultList();
        if (results == null || results.size() == 0) {
            return null;
        }
        return results.get(0).getId();
    }
}
