package gov.healthit.chpl.scheduler.job.urlStatus;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

import javax.mail.MessagingException;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import gov.healthit.chpl.dao.CertificationBodyDAO;
import gov.healthit.chpl.dao.CertificationResultDetailsDAO;
import gov.healthit.chpl.dao.CertifiedProductDAO;
import gov.healthit.chpl.dao.DeveloperDAO;
import gov.healthit.chpl.dao.TestingLabDAO;
import gov.healthit.chpl.dto.CertificationBodyDTO;
import gov.healthit.chpl.dto.CertificationResultDetailsDTO;
import gov.healthit.chpl.dto.CertifiedProductSummaryDTO;
import gov.healthit.chpl.dto.DeveloperDTO;
import gov.healthit.chpl.dto.TestingLabDTO;
import gov.healthit.chpl.exception.EntityRetrievalException;
import gov.healthit.chpl.scheduler.job.QuartzJob;
import gov.healthit.chpl.util.EmailBuilder;

/**
 * Quartz job to compile the results of the saved broken url data into a report.
 * @author kekey
 *
 */
public class QuestionableUrlReportGenerator extends QuartzJob {
    private static final Logger LOGGER = LogManager.getLogger("questionableUrlReportGeneratorJobLogger");
    private static final String[] CSV_HEADER = {
            "URL", "Status Code", "Status Name", "Error Message",
            "URL Type", "ONC-ATL", "ONC-ACB", "Developer", "Developer Contact Name",
            "Developer Contact Email", "Developer Contact Phone Number", "Product", "Version",
            "CHPL Product Number", "Edition", "Certification Date",
            "Certification Status", "Criteria", "Date Last Checked"};

    @Autowired
    private Environment env;

    @Autowired
    private UrlCheckerDao urlCheckerDao;

    @Autowired
    private TestingLabDAO atlDao;

    @Autowired
    private CertificationBodyDAO acbDao;

    @Autowired
    private DeveloperDAO devDao;

    @Autowired
    private CertifiedProductDAO cpDao;

    @Autowired
    private CertificationResultDetailsDAO certResultDao;

    @Override
    @Transactional
    public void execute(final JobExecutionContext jobContext) throws JobExecutionException {
        SpringBeanAutowiringSupport.processInjectionBasedOnCurrentContext(this);
        LOGGER.info("********* Starting the Questionable URL Report Generator job. *********");

        try {
            List<FailedUrlResult> badUrlsToWrite = new ArrayList<FailedUrlResult>();
            List<UrlResult> badUrls = urlCheckerDao.getUrlResultsWithError();
            LOGGER.info("Found " + badUrls.size() + " urls with errors.");
            int i = 0;
            for (UrlResult urlResult : badUrls) {
                switch (urlResult.getUrlType()) {
                case ACB:
                    LOGGER.info("[" + i + "]: Getting ACBs with bad website " + urlResult.getUrl());
                    List<CertificationBodyDTO> acbsWithBadUrl = acbDao.getByWebsite(urlResult.getUrl());
                    for (CertificationBodyDTO acb : acbsWithBadUrl) {
                        FailedUrlResult urlResultWithError = new FailedUrlResult(urlResult);
                        urlResultWithError.setAcbName(acb.getName());
                        badUrlsToWrite.add(urlResultWithError);
                    }
                    break;
                case ATL:
                    LOGGER.info("[" + i + "] Getting ATLs with bad website " + urlResult.getUrl());
                    List<TestingLabDTO> atlsWithBadUrl = atlDao.getByWebsite(urlResult.getUrl());
                    for (TestingLabDTO atl : atlsWithBadUrl) {
                        FailedUrlResult urlResultWithError = new FailedUrlResult(urlResult);
                        urlResultWithError.setAtlName(atl.getName());
                        badUrlsToWrite.add(urlResultWithError);
                    }
                    break;
                case DEVELOPER:
                    LOGGER.info("[ " + i + "] Getting Developers with bad website " + urlResult.getUrl());
                    List<DeveloperDTO> devsWithBadUrl = devDao.getByWebsite(urlResult.getUrl());
                    for (DeveloperDTO dev : devsWithBadUrl) {
                        FailedUrlResult urlResultWithError = new FailedUrlResult(urlResult);
                        urlResultWithError.setDeveloperName(dev.getName());
                        if (dev.getContact() != null) {
                            urlResultWithError.setContactEmail(dev.getContact().getEmail());
                            urlResultWithError.setContactName(dev.getContact().getFullName());
                            urlResultWithError.setContactPhone(dev.getContact().getPhoneNumber());
                        }
                        badUrlsToWrite.add(urlResultWithError);
                    }
                    break;
                case FULL_USABILITY_REPORT:
                case MANDATORY_DISCLOSURE_URL:
                case TEST_RESULTS_SUMMARY:
                    LOGGER.info("[" + i + "] Getting Listings with bad " + urlResult.getUrlType().getName() + " website " + urlResult.getUrl());
                    List<CertifiedProductSummaryDTO> listingsWithBadUrl =
                        cpDao.getSummaryByUrl(urlResult.getUrl(), urlResult.getUrlType());
                    for (CertifiedProductSummaryDTO listing : listingsWithBadUrl) {
                        FailedUrlResult urlResultWithError = new FailedUrlResult(urlResult);
                        if (listing.getAcb() != null) {
                            urlResultWithError.setAcbName(listing.getAcb().getName());
                        }
                        if (listing.getDeveloper() != null) {
                            DeveloperDTO dev = listing.getDeveloper();
                            urlResultWithError.setDeveloperName(dev.getName());
                            if (dev.getContact() != null) {
                                urlResultWithError.setContactEmail(dev.getContact().getEmail());
                                urlResultWithError.setContactName(dev.getContact().getFullName());
                                urlResultWithError.setContactPhone(dev.getContact().getPhoneNumber());
                            }
                        }
                        if (listing.getProduct() != null) {
                            urlResultWithError.setProductName(listing.getProduct().getName());
                        }
                        if (listing.getVersion() != null) {
                            urlResultWithError.setVersion(listing.getVersion().getVersion());
                        }
                        urlResultWithError.setChplProductNumber(listing.getChplProductNumber());
                        urlResultWithError.setEdition(listing.getYear());
                        urlResultWithError.setCertificationStatus(listing.getCertificationStatus());
                        urlResultWithError.setCertificationDate(listing.getCertificationDate());
                        badUrlsToWrite.add(urlResultWithError);
                    }
                    break;
                case API_DOCUMENTATION:
                    LOGGER.info("[" + i + "] Getting criteria with bad " + urlResult.getUrlType().getName() + " website " + urlResult.getUrl());
                    List<CertificationResultDetailsDTO> certResultsWithBadUrl =
                        certResultDao.getByUrl(urlResult.getUrl());
                    for (CertificationResultDetailsDTO certResult : certResultsWithBadUrl) {
                        //get the associated listing
                        CertifiedProductSummaryDTO associatedListing = null;
                        try {
                            associatedListing = cpDao.getSummaryById(certResult.getCertifiedProductId());
                        } catch (EntityRetrievalException ex) {
                            LOGGER.info("Could not find associated listing with id " + certResult.getCertifiedProductId());
                        }
                        if (associatedListing != null) {
                            FailedUrlResult urlResultWithError = new FailedUrlResult(urlResult);
                            if (associatedListing.getAcb() != null) {
                                urlResultWithError.setAcbName(associatedListing.getAcb().getName());
                            }
                            if (associatedListing.getDeveloper() != null) {
                                DeveloperDTO dev = associatedListing.getDeveloper();
                                urlResultWithError.setDeveloperName(dev.getName());
                                if (dev.getContact() != null) {
                                    urlResultWithError.setContactEmail(dev.getContact().getEmail());
                                    urlResultWithError.setContactName(dev.getContact().getFullName());
                                    urlResultWithError.setContactPhone(dev.getContact().getPhoneNumber());
                                }
                            }
                            if (associatedListing.getProduct() != null) {
                                urlResultWithError.setProductName(associatedListing.getProduct().getName());
                            }
                            if (associatedListing.getVersion() != null) {
                                urlResultWithError.setVersion(associatedListing.getVersion().getVersion());
                            }
                            urlResultWithError.setChplProductNumber(associatedListing.getChplProductNumber());
                            urlResultWithError.setEdition(associatedListing.getYear());
                            urlResultWithError.setCertificationStatus(associatedListing.getCertificationStatus());
                            urlResultWithError.setCertificationDate(associatedListing.getCertificationDate());
                            urlResultWithError.setCriteria(certResult.getNumber());
                            badUrlsToWrite.add(urlResultWithError);
                        }
                    }
                    break;
                default:
                    break;
                }
                i++;
            }

            //sort the bad urls first by url
            //and then by type
            Collections.sort(badUrlsToWrite, new Comparator<FailedUrlResult>() {
                @Override
                public int compare(final FailedUrlResult o1, final FailedUrlResult o2) {
                    if (o1.getUrl().equals(o2.getUrl())) {
                        return o1.getUrlType().ordinal() - o2.getUrlType().ordinal();
                    }
                    return o1.getUrl().compareTo(o2.getUrl());
                }
            });

            LOGGER.info("Creating email subject and body.");
            String to = jobContext.getMergedJobDataMap().getString("email");
            String subject = env.getProperty("job.questionableUrlReport.emailSubject");
            String htmlMessage = env.getProperty("job.questionableUrlReport.emailBodyBegin");
            htmlMessage += createHtmlEmailBody(badUrlsToWrite, env.getProperty("job.questionableUrlReport.emailBodyNoContent"));
            File output = null;
            List<File> files = new ArrayList<File>();
            if (badUrlsToWrite.size() > 0) {
                output = getOutputFile(badUrlsToWrite, env.getProperty("job.questionableUrlReport.emailAttachmentName"));
                files.add(output);
            }

            LOGGER.info("Sending email to {} with contents {} and a total of {} questionable URLs.",
                    to, htmlMessage, badUrlsToWrite.size());
            try {
                List<String> addresses = new ArrayList<String>();
                addresses.add(to);

                EmailBuilder emailBuilder = new EmailBuilder(env);
                emailBuilder.recipients(addresses)
                                .subject(subject)
                                .htmlMessage(htmlMessage)
                                .fileAttachments(files)
                                .sendEmail();
            } catch (MessagingException e) {
                LOGGER.error(e);
            }
        } catch (Exception ex) {
            LOGGER.error("Unable to complete job: " + ex.getMessage(), ex);
        }
        LOGGER.info("********* Completed the Questionable URL Report Generator job. *********");
    }

    /**
     * Generates a CSV output file with all bad url data.
     * @param urlResultsToWrite list of failed url data, sorted by url
     * @param reportFilename
     * @return
     */
    private File getOutputFile(final List<FailedUrlResult> urlResultsToWrite, final String reportFilename) {
        File temp = null;
        try {
            temp = File.createTempFile(reportFilename, ".csv");
            temp.deleteOnExit();
        } catch (IOException ex) {
            LOGGER.error("Could not create temporary file " + ex.getMessage(), ex);
        }

        if (temp != null) {
            try (OutputStreamWriter writer = new OutputStreamWriter(
                    new FileOutputStream(temp), Charset.forName("UTF-8").newEncoder());
                CSVPrinter csvPrinter = new CSVPrinter(writer, CSVFormat.EXCEL)) {
                csvPrinter.printRecord(getHeaderRow());
                //urlResultsToWrite must be sorted by url
                for (int i = 0; i < urlResultsToWrite.size(); i++) {
                    FailedUrlResult currUrlResult = urlResultsToWrite.get(i);
                    FailedUrlResult prevUrlResult = null;
                    if (i > 0) {
                        prevUrlResult = urlResultsToWrite.get(i-1);
                    }
                    List<String> rowValue = null;
                    if (prevUrlResult == null || !currUrlResult.getUrl().equals(prevUrlResult.getUrl())) {
                        //write a row with the url data since this url is different than the one before it
                        rowValue = generateRowValue(currUrlResult, true);
                    } else {
                        //write a row with just the acb/atl/developer/listing data since this is for the same url
                        //as the one before it
                        rowValue = generateRowValue(currUrlResult, false);
                    }
                    if (rowValue != null) {
                        csvPrinter.printRecord(rowValue);
                    }
                }
            } catch (IOException e) {
                LOGGER.error(e);
            }
        }
        return temp;
    }

    /**
     * Create an array of strings representing the header of a CSV.
     * @return
     */
    private List<String> getHeaderRow() {
        return Arrays.asList(CSV_HEADER);
    }

    /**
     * Create an array of strings representing one row of data in a CSV.
     * @param urlResult
     * @return
     */
    private List<String> generateRowValue(final FailedUrlResult urlResult, final boolean firstUrlInGroup) {
        List<String> result = new ArrayList<String>();
        if (firstUrlInGroup) {
            result.add(urlResult.getUrl());
            if (urlResult.getResponseCode() != null) {
                result.add(urlResult.getResponseCode().toString());
                try {
                    HttpStatus httpStatus = HttpStatus.valueOf(urlResult.getResponseCode());
                    if (httpStatus != null) {
                        result.add(httpStatus.getReasonPhrase());
                    } else {
                        result.add("");
                    }
                } catch (IllegalArgumentException ex) {
                    LOGGER.warn("No HttpStatus object could be found for response code " + urlResult.getResponseCode());
                    result.add("");
                }
            } else {
                result.add("");
                result.add("");
            }

            if (urlResult.getResponseMessage() != null) {
                result.add(urlResult.getResponseMessage());
            } else {
                result.add("");
            }
        } else {
            result.add("");
            result.add("");
            result.add("");
            result.add("");
        }

        result.add(urlResult.getUrlType().getName());

        if (urlResult.getAtlName() != null) {
            result.add(urlResult.getAtlName());
        } else {
            result.add("");
        }

        if (urlResult.getAcbName() != null) {
            result.add(urlResult.getAcbName());
        } else {
            result.add("");
        }

        if (urlResult.getDeveloperName() != null) {
            result.add(urlResult.getDeveloperName());
        } else {
            result.add("");
        }

        if (urlResult.getContactName() != null) {
            result.add(urlResult.getContactName());
        } else {
            result.add("");
        }

        if (urlResult.getContactEmail() != null) {
            result.add(urlResult.getContactEmail());
        } else {
            result.add("");
        }

        if (urlResult.getContactPhone() != null) {
            result.add(urlResult.getContactPhone());
        } else {
            result.add("");
        }

        if (urlResult.getProductName() != null) {
            result.add(urlResult.getProductName());
        } else {
            result.add("");
        }

        if (urlResult.getVersion() != null) {
            result.add(urlResult.getVersion());
        } else {
            result.add("");
        }

        if (urlResult.getChplProductNumber() != null) {
            result.add(urlResult.getChplProductNumber());
        } else {
            result.add("");
        }

        if (urlResult.getEdition() != null) {
            result.add(urlResult.getEdition());
        } else {
            result.add("");
        }

        if (urlResult.getCertificationDate() != null) {
            result.add(getDateFormatter().format(urlResult.getCertificationDate()));
        } else {
            result.add("");
        }

        if (urlResult.getCertificationStatus() != null) {
            result.add(urlResult.getCertificationStatus());
        } else {
            result.add("");
        }

        if (urlResult.getCriteria() != null) {
            result.add(urlResult.getCriteria());
        } else {
            result.add("");
        }

        if (urlResult.getLastChecked() != null) {
            result.add(getTimestampFormatter().format(urlResult.getLastChecked()));
        } else {
            result.add("");
        }
        return result;
    }

    /**
     * Create the HTML body of the email to be sent.
     * @param urlResults
     * @param noContentMsg
     * @return
     */
    private String createHtmlEmailBody(final List<FailedUrlResult> urlResults, final String noContentMsg) {
        String htmlMessage = "";
        if (urlResults.size() == 0) {
            htmlMessage = noContentMsg;
        } else {
            int brokenAcbUrls = getCountOfBrokenUrlsOfType(urlResults, UrlType.ACB);
            int brokenAtlUrls = getCountOfBrokenUrlsOfType(urlResults, UrlType.ATL);
            int brokenDeveloperUrls = getCountOfBrokenUrlsOfType(urlResults, UrlType.DEVELOPER);
            int brokenMandatoryDisclosureUrls = getCountOfBrokenUrlsOfType(urlResults, UrlType.MANDATORY_DISCLOSURE_URL);
            int brokenTestResultsSummaryUrls = getCountOfBrokenUrlsOfType(urlResults, UrlType.TEST_RESULTS_SUMMARY);
            int brokenFullUsabilityReportUrls = getCountOfBrokenUrlsOfType(urlResults, UrlType.FULL_USABILITY_REPORT);
            int brokenApiDocumentationUrls = getCountOfBrokenUrlsOfType(urlResults, UrlType.API_DOCUMENTATION);

            htmlMessage += "<ul>";
            htmlMessage += "<li>" + UrlType.ATL.getName() + ": " + brokenAtlUrls + "</li>";
            htmlMessage += "<li>" + UrlType.ACB.getName() + ": " + brokenAcbUrls + "</li>";
            htmlMessage += "<li>" + UrlType.DEVELOPER.getName() + ": " + brokenDeveloperUrls + "</li>";
            htmlMessage += "<li>" + UrlType.FULL_USABILITY_REPORT.getName() + ": " + brokenFullUsabilityReportUrls + "</li>";
            htmlMessage += "<li>" + UrlType.MANDATORY_DISCLOSURE_URL.getName() + ": " + brokenMandatoryDisclosureUrls + "</li>";
            htmlMessage += "<li>" + UrlType.TEST_RESULTS_SUMMARY.getName() + ": " + brokenTestResultsSummaryUrls + "</li>";
            htmlMessage += "<li>" + UrlType.API_DOCUMENTATION.getName() + ": " + brokenApiDocumentationUrls + "</li>";
            htmlMessage += "</ul>";
        }

        return htmlMessage;
    }

    private int getCountOfBrokenUrlsOfType(final List<FailedUrlResult> urlResults, final UrlType urlType) {
        int count = 0;
        for (FailedUrlResult urlResult : urlResults) {
            if (urlResult.getUrlType().equals(urlType)) {
                count++;
            }
        }
        return count;
    }

    private DateFormat getDateFormatter() {
        return DateFormat.getDateInstance(DateFormat.SHORT, Locale.US);
    }

    private DateFormat getTimestampFormatter() {
        return DateFormat.getDateTimeInstance(
                DateFormat.LONG,
                DateFormat.LONG,
                 Locale.US);
    }
}
