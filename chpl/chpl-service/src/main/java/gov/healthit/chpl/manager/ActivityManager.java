package gov.healthit.chpl.manager;

import gov.healthit.chpl.dao.EntityCreationException;
import gov.healthit.chpl.dao.EntityRetrievalException;
import gov.healthit.chpl.domain.ActivityConcept;
import gov.healthit.chpl.domain.ActivityEvent;
import gov.healthit.chpl.domain.ActivityEventSummary;
import gov.healthit.chpl.dto.ActivityDTO;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;

public interface ActivityManager {

	public void addActivity(ActivityConcept concept, Long objectId, String activityDescription, Object originalData, Object newData) throws EntityCreationException, EntityRetrievalException, JsonProcessingException;
	public void addActivity(ActivityConcept concept, Long objectId, String activityDescription, Object originalData, Object newData, Date timestamp) throws EntityCreationException, EntityRetrievalException, JsonProcessingException;
	public List<ActivityEventSummary> getAllActivity() throws JsonParseException, IOException;
	public List<ActivityEventSummary> getActivityForObject(ActivityConcept concept, Long objectId) throws JsonParseException, IOException;
	public List<ActivityEventSummary> getActivityForConcept(ActivityConcept concept) throws JsonParseException, IOException;
	public List<ActivityEventSummary> getAllActivityInLastNDays(Integer lastNDays) throws JsonParseException, IOException;
	public List<ActivityEventSummary> getActivityForObject(ActivityConcept concept, Long objectId, Integer lastNDays) throws JsonParseException, IOException;
	public List<ActivityEventSummary> getActivityForConcept(ActivityConcept concept, Integer lastNDays) throws JsonParseException, IOException;
	public void deleteActivity(Long toDelete) throws EntityRetrievalException;
	public Map<Long, List<ActivityEventSummary>> getActivityByUser() throws JsonParseException, IOException;
	public Map<Long, List<ActivityEventSummary>> getActivityByUserInLastNDays(Integer nDays) throws JsonParseException, IOException;
	public List<ActivityEventSummary> getActivityForUser(Long userId) throws JsonParseException, IOException;
	public List<ActivityEventSummary> getActivityForUserInLastNDays(Long userId, Integer nDays) throws JsonParseException, IOException;
	public ActivityEvent getActivityEventById(Long activityId) throws JsonParseException, IOException, EntityRetrievalException;
	
}