package gov.healthit.chpl.app;

import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

/**
 * TimePeriod objects with properties for a given segment in time
 * @author dlucas
 *
 */
public class TimePeriod {
	private Date startDate;
	private Date endDate;
	private Integer numDaysInPeriod;
	
	public TimePeriod(){
	}
	
	/**
	 * Creates a TimePeriod object using an endDate and the number of days to go back
	 * @param endDate - the last day to be included in the time period
	 * @param numDaysToGoBack - the number of days to go back from the end date to determine the start date of the time period
	 */
	public TimePeriod(Date endDate, Integer numDaysToGoBack){		
		this.setNumDaysInPeriod(numDaysToGoBack);
		Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		c.setTime(endDate);
		 // Get first day of time period
		 c.add(Calendar.DATE, - numDaysToGoBack);
		 // set time to midnight
		 c.set(Calendar.HOUR_OF_DAY, 0);
		 c.set(Calendar.MINUTE, 0);
		 c.set(Calendar.SECOND, 0);
		 c.set(Calendar.HOUR_OF_DAY, 0);
		 // Get period start date time
		 this.startDate = c.getTime();
		 // Get period end date
		 c.add(Calendar.DATE, numDaysToGoBack);
		 // Get time of period end date
		 this.endDate = c.getTime();
	}
	
	/**
	 * Creates a TimePeriod object using a start and end date
	 * @param startDate - the first day to be included in the time period
	 * @param endDate - the last day to be included in the time period
	 */
	public TimePeriod(Date startDate, Date endDate){
		 Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		 // set time to midnight
		 c.set(Calendar.HOUR_OF_DAY, 0);
		 c.set(Calendar.MINUTE, 0);
		 c.set(Calendar.SECOND, 0);
		 c.set(Calendar.HOUR_OF_DAY, 0);
		 
		 c.setTime(startDate);
		 this.startDate = c.getTime();
		 c.setTime(endDate);
		 this.endDate = c.getTime();
	}
	
	public Date getStartDate(){
		return this.startDate;
	}
	
	public void setStartDate(Date date){
		this.startDate = date;
	}
	
	public Date getEndDate(){
		return this.endDate;
	}
	
	public void setEndDate(Date date){
		this.endDate = date;
	}
	
	public Integer getNumDaysInPeriod(){
		return this.numDaysInPeriod;
	}
	
	public void setNumDaysInPeriod(Integer numDays){
		this.numDaysInPeriod = numDays;
	}
}