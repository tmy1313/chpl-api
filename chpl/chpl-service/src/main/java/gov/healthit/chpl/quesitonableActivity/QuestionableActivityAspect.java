package gov.healthit.chpl.quesitonableActivity;

import java.util.Date;
import java.util.List;

import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import gov.healthit.chpl.auth.Util;
import gov.healthit.chpl.dao.QuestionableActivityDAO;
import gov.healthit.chpl.domain.CertificationResult;
import gov.healthit.chpl.domain.CertifiedProductSearchDetails;
import gov.healthit.chpl.domain.concept.ActivityConcept;
import gov.healthit.chpl.domain.concept.QuestionableActivityTriggerConcept;
import gov.healthit.chpl.dto.DeveloperDTO;
import gov.healthit.chpl.dto.ProductDTO;
import gov.healthit.chpl.dto.ProductVersionDTO;
import gov.healthit.chpl.dto.questionableActivity.QuestionableActivityCertificationResultDTO;
import gov.healthit.chpl.dto.questionableActivity.QuestionableActivityDeveloperDTO;
import gov.healthit.chpl.dto.questionableActivity.QuestionableActivityListingDTO;
import gov.healthit.chpl.dto.questionableActivity.QuestionableActivityProductDTO;
import gov.healthit.chpl.dto.questionableActivity.QuestionableActivityTriggerDTO;
import gov.healthit.chpl.dto.questionableActivity.QuestionableActivityVersionDTO;
import gov.healthit.chpl.entity.CertificationStatusType;
import gov.healthit.chpl.util.CertificationResultRules;

@Component
@Aspect
public class QuestionableActivityAspect implements EnvironmentAware {
    @Autowired private Environment env;
    @Autowired private CertificationResultRules certResultRules;
    @Autowired private QuestionableActivityDAO questionableActivityDao;
    @Autowired private DeveloperQuestionableActivityProvider developerQuestionableActivityProvider;
    @Autowired private ProductQuestionableActivityProvider productQuestionableActivityProvider;
    @Autowired private VersionQuestionableActivityProvider versionQuestionableActivityProvider;
    @Autowired private ListingQuestionableActivityProvider listingQuestionableActivityProvider;
    @Autowired private CertificationResultQuestionableActivityProvider certResultQuestionableActivityProvider;

    private List<QuestionableActivityTriggerDTO> triggerTypes;
    private long listingActivityThresholdMillis = -1;
    
    public QuestionableActivityAspect() {
    }
    
    @Override
    public void setEnvironment(final Environment e) {
        this.env = e;
        String activityThresholdDaysStr = env.getProperty("questionableActivityThresholdDays");
        int activityThresholdDays = new Integer(activityThresholdDaysStr).intValue();
        listingActivityThresholdMillis = activityThresholdDays * 24 * 60 * 60 * 1000;
        
        triggerTypes = questionableActivityDao.getAllTriggers();
    }
    
    @After("execution(* gov.healthit.chpl.manager.impl.ActivityManagerImpl.addActivity(..)) && "
            + "args(concept,objectId,activityDescription,originalData,newData,..)")
    public void checkQuestionableActivity(ActivityConcept concept, 
            Long objectId, String activityDescription, Object originalData, Object newData) {
        if(originalData == null || newData == null || 
                !originalData.getClass().equals(newData.getClass())) {
            return;
        }
        
        //all questionable activity from this action should have the exact same date and user id
        Date activityDate = new Date();
        Long activityUser = Util.getCurrentUser().getId();
        
        if(originalData instanceof CertifiedProductSearchDetails && 
                newData instanceof CertifiedProductSearchDetails) {
            CertifiedProductSearchDetails origListing = (CertifiedProductSearchDetails)originalData;
            CertifiedProductSearchDetails newListing = (CertifiedProductSearchDetails)newData;
            
            //look for any of the listing questionable activity
            checkListingQuestionableActivity(origListing, newListing, activityDate, activityUser);

            //look for certification result questionable activity
            if (origListing.getCertificationResults() != null && origListing.getCertificationResults().size() > 0 && 
                newListing.getCertificationResults() != null && newListing.getCertificationResults().size() > 0) {
                
                //all cert results are in the details so find matches based on the 
                //original and new criteira number fields
                for (CertificationResult origCertResult : origListing.getCertificationResults()) {
                    for (CertificationResult newCertResult : newListing.getCertificationResults()) {
                        if (origCertResult.getNumber().equals(newCertResult.getNumber())) {
                            checkCertificationResultQuestionableActivity(origCertResult, newCertResult, 
                                    activityDate, activityUser);
                        }
                    }
                }
            }
        } else if(originalData instanceof DeveloperDTO && newData instanceof DeveloperDTO) {
            DeveloperDTO origDeveloper = (DeveloperDTO)originalData;
            DeveloperDTO newDeveloper = (DeveloperDTO)newData;
            checkDeveloperQuestionableActivity(origDeveloper, newDeveloper, activityDate, activityUser);
        } else if(originalData instanceof ProductDTO && newData instanceof ProductDTO) {
            ProductDTO origProduct = (ProductDTO)originalData;
            ProductDTO newProduct = (ProductDTO)newData;
            checkProductQuestionableActivity(origProduct, newProduct, activityDate, activityUser);
        } else if(originalData instanceof ProductVersionDTO && newData instanceof ProductVersionDTO) {
            ProductVersionDTO origVersion = (ProductVersionDTO)originalData;
            ProductVersionDTO newVersion = (ProductVersionDTO)newData;
            checkVersionQuestionableActivity(origVersion, newVersion, activityDate, activityUser);
        }
    }    
    
    /**
     * checks for developer name changes, current status change, or status history change (add remove and edit)
     * @param origDeveloper
     * @param newDeveloper
     * @param activityDate
     * @param activityUser
     */
    private void checkDeveloperQuestionableActivity(DeveloperDTO origDeveloper, DeveloperDTO newDeveloper,
            Date activityDate, Long activityUser) {
        QuestionableActivityDeveloperDTO devActivity = null;
        List<QuestionableActivityDeveloperDTO> devActivities = null;
        
        devActivity = developerQuestionableActivityProvider.checkNameUpdated(origDeveloper, newDeveloper);
        if(devActivity != null) {
            createDeveloperActivity(devActivity, newDeveloper.getId(), activityDate, 
                    activityUser, QuestionableActivityTriggerConcept.DEVELOPER_NAME_EDITED);
        }
        
        devActivity = developerQuestionableActivityProvider.checkCurrentStatusChanged(origDeveloper, newDeveloper);
        if(devActivity != null) {
            createDeveloperActivity(devActivity, newDeveloper.getId(), activityDate, 
                    activityUser, QuestionableActivityTriggerConcept.DEVELOPER_STATUS_EDITED);
        }
        
        devActivities = developerQuestionableActivityProvider.checkStatusHistoryAdded(
                origDeveloper.getStatusEvents(), newDeveloper.getStatusEvents());
        if(devActivities != null && devActivities.size() > 0) {
            for(QuestionableActivityDeveloperDTO currDevActivity : devActivities) {
                createDeveloperActivity(currDevActivity, newDeveloper.getId(), activityDate, 
                        activityUser, QuestionableActivityTriggerConcept.DEVELOPER_STATUS_HISTORY_ADDED);
            }
        }
        
        devActivities = developerQuestionableActivityProvider.checkStatusHistoryRemoved(
                origDeveloper.getStatusEvents(), newDeveloper.getStatusEvents());
        if(devActivities != null && devActivities.size() > 0) {
            for(QuestionableActivityDeveloperDTO currDevActivity : devActivities) {
                createDeveloperActivity(currDevActivity, newDeveloper.getId(), activityDate, 
                        activityUser, QuestionableActivityTriggerConcept.DEVELOPER_STATUS_HISTORY_REMOVED);
            }
        }
        
        devActivities = developerQuestionableActivityProvider.checkStatusHistoryItemEdited(
                origDeveloper.getStatusEvents(), newDeveloper.getStatusEvents());
        if(devActivities != null && devActivities.size() > 0) {
            for(QuestionableActivityDeveloperDTO currDevActivity : devActivities) {
                createDeveloperActivity(currDevActivity, newDeveloper.getId(), activityDate, 
                        activityUser, QuestionableActivityTriggerConcept.DEVELOPER_STATUS_HISTORY_EDITED);
            }
        }
    }
    
    /**
     * checks for product name change, current owner change, owner history change (add remove and edit)
     * @param origProduct
     * @param newProduct
     * @param activityDate
     * @param activityUser
     */
    private void checkProductQuestionableActivity(ProductDTO origProduct, ProductDTO newProduct,
            Date activityDate, Long activityUser) {
        QuestionableActivityProductDTO productActivity = null;
        List<QuestionableActivityProductDTO> productActivities = null;
        
        productActivity = productQuestionableActivityProvider.checkNameUpdated(origProduct, newProduct);
        if(productActivity != null) {
            createProductActivity(productActivity, newProduct.getId(), activityDate, 
                    activityUser, QuestionableActivityTriggerConcept.PRODUCT_NAME_EDITED);
        }
        
        productActivity = productQuestionableActivityProvider.checkCurrentOwnerChanged(origProduct, newProduct);
        if(productActivity != null) {
            createProductActivity(productActivity, newProduct.getId(), activityDate, 
                    activityUser, QuestionableActivityTriggerConcept.PRODUCT_OWNER_EDITED);
        }
        
        productActivities = productQuestionableActivityProvider.checkOwnerHistoryAdded(origProduct.getOwnerHistory(), 
                newProduct.getOwnerHistory());
        if(productActivities != null && productActivities.size() > 0) {
            for(QuestionableActivityProductDTO currProductActivity : productActivities) {
                createProductActivity(currProductActivity, newProduct.getId(), activityDate, 
                        activityUser, QuestionableActivityTriggerConcept.PRODUCT_OWNER_HISTORY_ADDED);
            }
        }
        
        productActivities = productQuestionableActivityProvider.checkOwnerHistoryRemoved(origProduct.getOwnerHistory(), 
                newProduct.getOwnerHistory());
        if(productActivities != null && productActivities.size() > 0) {
            for(QuestionableActivityProductDTO currProductActivity : productActivities) {
                createProductActivity(currProductActivity, newProduct.getId(), activityDate, 
                        activityUser, QuestionableActivityTriggerConcept.PRODUCT_OWNER_HISTORY_REMOVED);
            }
        }
        
        productActivities = productQuestionableActivityProvider.checkOwnerHistoryItemEdited(
                origProduct.getOwnerHistory(), newProduct.getOwnerHistory());
        if(productActivities != null && productActivities.size() > 0) {
            for(QuestionableActivityProductDTO currProductActivity : productActivities) {
                createProductActivity(currProductActivity, newProduct.getId(), activityDate, 
                        activityUser, QuestionableActivityTriggerConcept.PRODUCT_OWNER_HISTORY_EDITED);
            }
        }
    }
   
    /**
     * checks for version name change
     * @param origVersion
     * @param newVersion
     * @param activityDate
     * @param activityUser
     */
    private void checkVersionQuestionableActivity(ProductVersionDTO origVersion, ProductVersionDTO newVersion,
            Date activityDate, Long activityUser) {
        QuestionableActivityVersionDTO activity = 
                versionQuestionableActivityProvider.checkNameUpdated(origVersion, newVersion);
        if(activity != null) {
            createVersionActivity(activity, origVersion.getId(), activityDate, 
                    activityUser, QuestionableActivityTriggerConcept.VERSION_NAME_EDITED);
        }
    }
    
    /**
     * checks for various listing changes - add or remove certs and cqms, deleting surveillance, 
     * editing certification date
     * @param origListing
     * @param newListing
     * @param activityDate
     * @param activityUser
     */
    private void checkListingQuestionableActivity(CertifiedProductSearchDetails origListing, 
            CertifiedProductSearchDetails newListing, Date activityDate, Long activityUser) {
        QuestionableActivityListingDTO activity = listingQuestionableActivityProvider.check2011EditionUpdated(origListing, newListing);
        if(activity != null) {
            createListingActivity(activity, origListing.getId(), activityDate, activityUser, QuestionableActivityTriggerConcept.EDITION_2011_EDITED);
        } else {
            //it wasn't a 2011 update, check for any changes that are questionable
            //outside of the acceptable activity threshold
            activity = listingQuestionableActivityProvider.checkCertificationStatusUpdated(
                    CertificationStatusType.WithdrawnByDeveloperUnderReview, origListing, newListing);
            if(activity != null) {
                createListingActivity(activity, origListing.getId(), activityDate, activityUser, QuestionableActivityTriggerConcept.CERTIFICATION_STATUS_EDITED);
            }
            
            //finall check for other changes that are only questionable 
            //outside of the acceptable activity threshold
            if (origListing.getCertificationDate() != null && newListing.getCertificationDate() != null
                    && (newListing.getLastModifiedDate().longValue()
                            - origListing.getCertificationDate().longValue() > listingActivityThresholdMillis)) {
                activity = listingQuestionableActivityProvider.checkCertificationStatusUpdated(origListing, newListing);
                if(activity != null) {
                    createListingActivity(activity, origListing.getId(), activityDate, 
                            activityUser, QuestionableActivityTriggerConcept.CERTIFICATION_STATUS_EDITED);
                }
                
                activity = listingQuestionableActivityProvider.checkSurveillanceDeleted(origListing, newListing);
                if(activity != null) {
                    createListingActivity(activity, origListing.getId(), activityDate, 
                            activityUser, QuestionableActivityTriggerConcept.SURVEILLANCE_REMOVED);
                }
                
                List<QuestionableActivityListingDTO> activities = listingQuestionableActivityProvider.checkCqmsAdded(origListing, newListing);
                if(activities != null && activities.size() > 0) {
                    for(QuestionableActivityListingDTO currActivity : activities) {
                        createListingActivity(currActivity, origListing.getId(), activityDate, 
                                activityUser, QuestionableActivityTriggerConcept.CQM_ADDED);
                    }
                }
                
                activities = listingQuestionableActivityProvider.checkCqmsRemoved(origListing, newListing);
                if(activities != null && activities.size() > 0) {
                    for(QuestionableActivityListingDTO currActivity : activities) {
                        createListingActivity(currActivity, origListing.getId(), activityDate, 
                                activityUser, QuestionableActivityTriggerConcept.CQM_REMOVED);
                    }
                }

                activities = listingQuestionableActivityProvider.checkCertificationsAdded(origListing, newListing);
                if(activities != null && activities.size() > 0) {
                    for(QuestionableActivityListingDTO currActivity : activities) {
                        createListingActivity(currActivity, origListing.getId(), activityDate, 
                                activityUser, QuestionableActivityTriggerConcept.CRITERIA_ADDED);
                    }
                }
                
                activities = listingQuestionableActivityProvider.checkCertificationsRemoved(origListing, newListing);
                if(activities != null && activities.size() > 0) {
                    for(QuestionableActivityListingDTO currActivity : activities) {
                        createListingActivity(currActivity, origListing.getId(), activityDate, 
                                activityUser, QuestionableActivityTriggerConcept.CRITERIA_REMOVED);
                    }
                }
            }
        }
    }
    
    /**
     * checks for changes to listing certification results; g1/g2 boolean changes, macra measures added
     * or removed for g1/g2, or changes to gap
     * @param origCertResult
     * @param newCertResult
     * @param activityDate
     * @param activityUser
     */
    private void checkCertificationResultQuestionableActivity(CertificationResult origCertResult, CertificationResult newCertResult,
            Date activityDate, Long activityUser) {
        QuestionableActivityCertificationResultDTO certActivity = null;
        List<QuestionableActivityCertificationResultDTO> certActivities = null;
        
        if(certResultRules.hasCertOption(origCertResult.getNumber(), CertificationResultRules.G1_SUCCESS)) {
            certActivity = certResultQuestionableActivityProvider.checkG1SuccessUpdated(origCertResult, newCertResult);
            if(certActivity != null) {
                createCertificationActivity(certActivity, origCertResult.getId(), activityDate, 
                        activityUser, QuestionableActivityTriggerConcept.G1_SUCCESS_EDITED);
            }
        }
        if(certResultRules.hasCertOption(origCertResult.getNumber(), CertificationResultRules.G2_SUCCESS)) {
            certActivity = certResultQuestionableActivityProvider.checkG2SuccessUpdated(origCertResult, newCertResult);
            if(certActivity != null) {
                createCertificationActivity(certActivity, origCertResult.getId(), activityDate, 
                        activityUser, QuestionableActivityTriggerConcept.G2_SUCCESS_EDITED);
            }
        }
        if(certResultRules.hasCertOption(origCertResult.getNumber(), CertificationResultRules.GAP)) {
            certActivity = certResultQuestionableActivityProvider.checkGapUpdated(origCertResult, newCertResult);
            if(certActivity != null) {
                createCertificationActivity(certActivity, origCertResult.getId(), activityDate, 
                        activityUser, QuestionableActivityTriggerConcept.GAP_EDITED);
            }
        }
        if(certResultRules.hasCertOption(origCertResult.getNumber(), CertificationResultRules.G1_MACRA)) {
            certActivities = certResultQuestionableActivityProvider.checkG1MacraMeasuresAdded(origCertResult, newCertResult);
            if(certActivities != null && certActivities.size() > 0) {
                for(QuestionableActivityCertificationResultDTO currCertActivity : certActivities) {
                    createCertificationActivity(currCertActivity, origCertResult.getId(), activityDate, 
                            activityUser, QuestionableActivityTriggerConcept.G1_MEASURE_ADDED);
                }
            }
        }
        if(certResultRules.hasCertOption(origCertResult.getNumber(), CertificationResultRules.G1_MACRA)) {
            certActivities = certResultQuestionableActivityProvider.checkG1MacraMeasuresRemoved(origCertResult, newCertResult);
            if(certActivities != null && certActivities.size() > 0) {
                for(QuestionableActivityCertificationResultDTO currCertActivity : certActivities) {
                    createCertificationActivity(currCertActivity, origCertResult.getId(), activityDate, 
                            activityUser, QuestionableActivityTriggerConcept.G1_MEASURE_REMOVED);
                }
            }
        }
        if(certResultRules.hasCertOption(origCertResult.getNumber(), CertificationResultRules.G2_MACRA)) {
            certActivities = certResultQuestionableActivityProvider.checkG2MacraMeasuresAdded(origCertResult, newCertResult);
            if(certActivities != null && certActivities.size() > 0) {
                for(QuestionableActivityCertificationResultDTO currCertActivity : certActivities) {
                    createCertificationActivity(currCertActivity, origCertResult.getId(), activityDate, 
                            activityUser, QuestionableActivityTriggerConcept.G2_MEASURE_ADDED);
                }
            }
        }
        if(certResultRules.hasCertOption(origCertResult.getNumber(), CertificationResultRules.G2_MACRA)) {
            certActivities = certResultQuestionableActivityProvider.checkG2MacraMeasuresRemoved(origCertResult, newCertResult);
            if(certActivities != null && certActivities.size() > 0) {
                for(QuestionableActivityCertificationResultDTO currCertActivity : certActivities) {
                    createCertificationActivity(currCertActivity, origCertResult.getId(), activityDate, 
                            activityUser, QuestionableActivityTriggerConcept.G2_MEASURE_REMOVED);
                }
            }
        }
    }
    
    private void createListingActivity(QuestionableActivityListingDTO activity, Long listingId, 
            Date activityDate, Long activityUser, QuestionableActivityTriggerConcept trigger) {
        activity.setListingId(listingId);
        activity.setActivityDate(activityDate);
        activity.setUserId(activityUser);
        QuestionableActivityTriggerDTO triggerDto = getTrigger(trigger);
        activity.setTriggerId(triggerDto.getId());
        questionableActivityDao.create(activity);
    }
    
    private void createCertificationActivity(QuestionableActivityCertificationResultDTO activity, Long certResultId, 
            Date activityDate, Long activityUser, QuestionableActivityTriggerConcept trigger) {
        activity.setCertResultId(certResultId);
        activity.setActivityDate(activityDate);
        activity.setUserId(activityUser);
        QuestionableActivityTriggerDTO triggerDto = getTrigger(trigger);
        activity.setTriggerId(triggerDto.getId());
        questionableActivityDao.create(activity);
    }
    
    private void createDeveloperActivity(QuestionableActivityDeveloperDTO activity, Long developerId, 
            Date activityDate, Long activityUser, QuestionableActivityTriggerConcept trigger) {
        activity.setDeveloperId(developerId);
        activity.setActivityDate(activityDate);
        activity.setUserId(activityUser);
        QuestionableActivityTriggerDTO triggerDto = getTrigger(trigger);
        activity.setTriggerId(triggerDto.getId());
        questionableActivityDao.create(activity);
    }
    
    private void createProductActivity(QuestionableActivityProductDTO activity, Long productId, 
            Date activityDate, Long activityUser, QuestionableActivityTriggerConcept trigger) {
        activity.setProductId(productId);
        activity.setActivityDate(activityDate);
        activity.setUserId(activityUser);
        QuestionableActivityTriggerDTO triggerDto = getTrigger(trigger);
        activity.setTriggerId(triggerDto.getId());        
        questionableActivityDao.create(activity);
    }
    
    private void createVersionActivity(QuestionableActivityVersionDTO activity, Long versionId, 
            Date activityDate, Long activityUser, QuestionableActivityTriggerConcept trigger) {
        activity.setVersionId(versionId);
        activity.setActivityDate(activityDate);
        activity.setUserId(activityUser);
        QuestionableActivityTriggerDTO triggerDto = getTrigger(trigger);
        activity.setTriggerId(triggerDto.getId());
        questionableActivityDao.create(activity);
    }
    
    private QuestionableActivityTriggerDTO getTrigger(QuestionableActivityTriggerConcept trigger) {
        QuestionableActivityTriggerDTO result = null;
        for(QuestionableActivityTriggerDTO currTrigger : triggerTypes) {
            if(trigger.getName().equalsIgnoreCase(currTrigger.getName())) {
                result = currTrigger;
            }
        }
        return result;
    }
}
