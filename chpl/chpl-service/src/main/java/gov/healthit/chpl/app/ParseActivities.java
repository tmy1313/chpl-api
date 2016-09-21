package gov.healthit.chpl.app;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.TimeZone;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.support.AbstractApplicationContext;
import org.springframework.stereotype.Component;

import gov.healthit.chpl.dao.CertifiedProductDAO;
import gov.healthit.chpl.dao.DeveloperDAO;
import gov.healthit.chpl.dao.ProductDAO;
import gov.healthit.chpl.domain.AggregateCount;
import gov.healthit.chpl.dto.CertifiedProductDetailsDTO;
import gov.healthit.chpl.dto.DeveloperDTO;
import gov.healthit.chpl.dto.ProductDTO;

@Component("parseActivities")
public class ParseActivities{
	private static final String DEFAULT_PROPERTIES_FILE = "environment.properties";
	private static final Logger logger = LogManager.getLogger(ParseActivities.class);
	private DeveloperDAO developerDAO;
	private CertifiedProductDAO certifiedProductDAO;
	private ProductDAO productDAO;
	
	public ParseActivities(){
	}

	public static void main( String[] args ) throws Exception {
		// Command-line argument [0]
		Date startDate = new Date();
		// Command-line argument [1]
		Date endDate = new Date();
		// Command-line argument [2]
		Integer numDaysInPeriod = 7;
		Integer numArgs = args.length;
		SimpleDateFormat isoFormat = new SimpleDateFormat("yyyy-MM-dd");
		isoFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
		Properties props = null;
		InputStream in = App.class.getClassLoader().getResourceAsStream(DEFAULT_PROPERTIES_FILE);
		
		// Check # of command-line arguments
		switch(numArgs){
		case 0:
			throw new Exception("ParseActivities expects two or three command-line arguments: startDate, endDate and optionally numDaysInPeriod");
		case 1:
			throw new Exception("ParseActivities expects two or three command-line arguments: startDate, endDate and optionally numDaysInPeriod");
		case 2:
			try{
				startDate = isoFormat.parse(args[0]);
				endDate = isoFormat.parse(args[1]);
			}
			catch(ParseException e){
				throw new ParseException("Please enter startDate and endDate command-line arguments in the format of yyyy-MM-dd", e.getErrorOffset());
			}
			break;
		case 3:
			try{
				startDate = isoFormat.parse(args[0]);
				endDate = isoFormat.parse(args[1]);
			}
			catch(ParseException e){
				throw new ParseException("Please enter startDate and endDate command-line arguments in the format of yyyy-MM-dd", e.getErrorOffset());
			}
			try{
				Integer numDaysArg = Integer.parseInt(args[2]);
				numDaysInPeriod = numDaysArg;
			} catch(NumberFormatException e){
				System.out.println("Third command line argument could not be parsed to integer. " + e.getMessage());
			}
			break;
		}	
		
		// Parse startDate and endDate from command-line arguments
		
		
		// Load properties from Environment.properties
		if (in == null) {
			props = null;
			throw new FileNotFoundException("Environment Properties File not found in class path.");
		} else {
			props = new Properties();
			props.load(in);
			in.close();
		}
		
		//set up data source context
		 LocalContext ctx = LocalContextFactory.createLocalContext(props.getProperty("dbDriverClass"));
		 ctx.addDataSource(props.getProperty("dataSourceName"),props.getProperty("dataSourceConnection"), 
				 props.getProperty("dataSourceUsername"), props.getProperty("dataSourcePassword"));
		 
		 //init spring classes
		 AbstractApplicationContext context = new AnnotationConfigApplicationContext(AppConfig.class);
		 System.out.println(context.getClassLoader());
		 ParseActivities parseActivities = new ParseActivities();
		 parseActivities.setDeveloperDAO((DeveloperDAO)context.getBean("developerDAO"));
		 parseActivities.setCertifiedProductDAO((CertifiedProductDAO)context.getBean("certifiedProductDAO"));
		 parseActivities.setProductDAO((ProductDAO)context.getBean("productDAO"));
		 
		 // get DTOs
		 List<DeveloperDTO> developerDTOs = parseActivities.developerDAO.findAll();
		 List<CertifiedProductDetailsDTO> certifiedProductDTOs = parseActivities.certifiedProductDAO.findAll();
		 List<ProductDTO> productDTOs = parseActivities.productDAO.findAll();
		 
		 // Populate CPs_2014 and CPs_2015
		 List<CertifiedProductDetailsDTO> certifiedProductDTOs_2014 = new ArrayList<CertifiedProductDetailsDTO>();
		 List<CertifiedProductDetailsDTO> certifiedProductDTOs_2015 = new ArrayList<CertifiedProductDetailsDTO>();
		 for(CertifiedProductDetailsDTO dto : certifiedProductDTOs){
			 if(dto.getYear() == "2014"){
				 certifiedProductDTOs_2014.add(dto);
			 }
			 else if(dto.getYear() == "2015"){
				 certifiedProductDTOs_2015.add(dto);
			 }
		 }
		 
		 // 1. Get startDate & endDate for most recent week (defined as Sunday-Saturday)
		 // Note: outputMap date key has latest day in a given week of data
		 // Note2: totals for each each value of ActivitiesOutput are rolling values that show totals up to the key value
		 Calendar calendarCounter = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		 calendarCounter.setTime(endDate);
		 while(startDate.before(calendarCounter.getTime())){
			 Date counterDate = calendarCounter.getTime();
			 TimePeriod timePeriod = new TimePeriod(counterDate, numDaysInPeriod);

			 // Get aggregate count for developers
			 AggregateCount developerCount = new AggregateCount(developerDTOs);
			 Integer totalDevelopers = developerCount.getCountDuringPeriodUsingField(timePeriod.getStartDate(), timePeriod.getEndDate(), "creationDate");
			 // Get aggregate count for products
			 AggregateCount productCount = new AggregateCount(productDTOs);
			 Integer totalProducts = developerCount.getCountDuringPeriodUsingField(timePeriod.getStartDate(), timePeriod.getEndDate(), "creationDate");
			 // Get aggregate count for certified products
			 AggregateCount certifiedProductCount = new AggregateCount(certifiedProductDTOs);
			 Integer totalCertifiedProducts = developerCount.getCountDuringPeriodUsingField(timePeriod.getStartDate(), timePeriod.getEndDate(), "creationDate");
			 // Get aggregate count for CPs_2014
			 AggregateCount certifiedProductCount_2014 = new AggregateCount(certifiedProductDTOs_2014);
			 Integer totalCertifiedProducts_2014 = developerCount.getCountDuringPeriodUsingField(timePeriod.getStartDate(), timePeriod.getEndDate(), "creationDate");
			 // Get aggregate count for CPs_2015
			 AggregateCount certifiedProductCount_2015 = new AggregateCount(certifiedProductDTOs_2015);
			 Integer totalCertifiedProducts_2015 = developerCount.getCountDuringPeriodUsingField(timePeriod.getStartDate(), timePeriod.getEndDate(), "creationDate");
			 
			 // Populate ActivitiesOutput
			 //ActivitiesOutput activitiesOutput = new ActivitiesOutput();
			 //activitiesOutput.setTotalDevelopers(totalDevelopers);
			 
			 // Populate outputMap
			 HashMap <Date, ActivitiesOutput> outputMap = new HashMap <Date, ActivitiesOutput>();
			 //outputMap.put(counterDate, value);
			 
			// decrement calendar by 7 days
			 calendarCounter.add(Calendar.DATE, -numDaysInPeriod);
			 // Test output
			 System.out.println(timePeriod.getStartDate().toString() + " - " + timePeriod.getEndDate().toString() + "\n");
			 System.out.println("Total developers: " + totalDevelopers + "\n");
			 System.out.println("Total products: " + totalProducts + "\n");
			 System.out.println("Total certified products: " + totalCertifiedProducts + "\n");
			 System.out.println("Total certified products in 2014: " + certifiedProductCount_2014 + "\n");
			 System.out.println("Total certified products in 2015: " + certifiedProductCount_2015 + "\n");
		 }
		 
		 // Generate HTML for email using outputMap
		 
		 
	}
	
	public DeveloperDAO getDeveloperDAO() {
		return developerDAO;
	}

	public void setDeveloperDAO(DeveloperDAO developerDAO) {
		this.developerDAO = developerDAO;
	}
	
	public CertifiedProductDAO getCertifiedProductDAO() {
		return certifiedProductDAO;
	}

	public void setCertifiedProductDAO(CertifiedProductDAO certifiedProductDAO) {
		this.certifiedProductDAO = certifiedProductDAO;
	}
	
	public ProductDAO getProductDAO() {
		return productDAO;
	}

	public void setProductDAO(ProductDAO productDAO) {
		this.productDAO = productDAO;
	}

}
