package gov.healthit.chpl.scheduler.job.summarystatistics;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.TimeZone;

import javax.mail.MessagingException;
import javax.mail.internet.AddressException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import gov.healthit.chpl.dao.CertificationBodyDAO;
import gov.healthit.chpl.dao.statistics.SummaryStatisticsDAO;
import gov.healthit.chpl.domain.statistics.CertifiedBodyAltTestStatistics;
import gov.healthit.chpl.domain.statistics.CertifiedBodyStatistics;
import gov.healthit.chpl.domain.statistics.Statistics;
import gov.healthit.chpl.dto.CertificationBodyDTO;
import gov.healthit.chpl.entity.SummaryStatisticsEntity;
import gov.healthit.chpl.scheduler.job.QuartzJob;
import gov.healthit.chpl.util.EmailBuilder;

/**
 * The SummaryStatisticsEmailJob implements a Quartz job and is schedulable by ADMINs.  When the job is triggered,
 * it will send the recipient an email with summary statistics of the CHPL data.
 * @author TYoung
 *
 */
public class SummaryStatisticsEmailJob extends QuartzJob {
    private static final Logger LOGGER = LogManager.getLogger("summaryStatisticsEmailJobLogger");
    private static final String DEFAULT_PROPERTIES_FILE = "environment.properties";
    private static final int EDITION2014 = 2014;
    private static final int EDITION2015 = 2015;

    @Autowired
    private SummaryStatisticsDAO summaryStatisticsDAO;

    @Autowired
    private CertificationBodyDAO certificationBodyDAO;

    @Autowired
    private Environment env;

    private Properties props;

    private List<CertificationBodyDTO> activeAcbs;

    /**
     * Constructor that initializes the SummaryStatisticsEmailJob object.
     * @throws Exception if thrown
     */
    public SummaryStatisticsEmailJob() throws Exception {
        super();
        loadProperties();
    }

    @Override
    public void execute(final JobExecutionContext jobContext) throws JobExecutionException {
        try {
            SpringBeanAutowiringSupport.processInjectionBasedOnCurrentContext(this);
            LOGGER.info("********* Starting the Summary Statistics Email job. *********");
            LOGGER.info("Sending email to: " + jobContext.getMergedJobDataMap().getString("email"));

            activeAcbs = certificationBodyDAO.findAllActive();

            SummaryStatisticsEntity summaryStatistics = summaryStatisticsDAO.getCurrentSummaryStatistics();
            Statistics stats = getStatistics(summaryStatistics);
            String message = createHtmlMessage(stats, summaryStatistics.getEndDate());
            LOGGER.info("Message to be sent: " + message);
            sendEmail(message, jobContext.getMergedJobDataMap().getString("email"));
        } catch (Exception e) {
            LOGGER.error("Caught unexpected exception: " + e.getMessage(), e);
        } finally {
            LOGGER.info("********* Completed the Summary Statistics Email job. *********");
        }
    }

    private void sendEmail(final String message, final String address) throws AddressException, MessagingException {
        String subject = props.getProperty("summaryEmailSubject").toString();

        List<String> addresses = new ArrayList<String>();
        addresses.add(address);

        EmailBuilder emailBuilder = new EmailBuilder(env);
        emailBuilder.recipients(addresses).subject(subject).htmlMessage(message)
                .fileAttachments(getSummaryStatisticsFile()).sendEmail();
    }

    private List<File> getSummaryStatisticsFile() {
        List<File> files = new ArrayList<File>();
        File file = new File(System.getenv("downloadFolderPath") + File.separator
                + props.getProperty("summaryEmailName", "summaryStatistics.csv"));
        files.add(file);
        return files;
    }

    private Statistics getStatistics(final SummaryStatisticsEntity summaryStatistics)
            throws JsonParseException, JsonMappingException, IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(summaryStatistics.getSummaryStatistics(), Statistics.class);
    }

    private String createHtmlMessage(final Statistics stats, final Date endDate) {
        StringBuilder emailMessage = new StringBuilder();

        emailMessage.append(createMessageHeader(endDate));
        emailMessage.append(createUniqueDeveloperSection(stats));
        emailMessage.append(createUniqueProductSection(stats));
        emailMessage.append(createListingSection(stats));

        emailMessage.append(
                "<h4>Total # of Surveillance Activities -  " + stats.getTotalSurveillanceActivities() + "</h4>");
        emailMessage.append(
                "<ul><li>Open Surveillance Activities - " + stats.getTotalOpenSurveillanceActivities() + "</li>");

        emailMessage.append("<ul>");
        for (CertifiedBodyStatistics stat : getStatistics(stats.getTotalOpenSurveillanceActivitiesByAcb())) {
            emailMessage.append("<li>Certified by ");
            emailMessage.append(stat.getName());
            emailMessage.append(" - ");
            emailMessage.append(stat.getTotalListings().toString());
            emailMessage.append("</li>");
        }
        emailMessage.append("</ul>");

        emailMessage.append(
                "<li>Closed Surveillance Activities - " + stats.getTotalClosedSurveillanceActivities() + "</li></ul>");
        emailMessage.append("<h4>Total # of NCs -  " + stats.getTotalNonConformities() + "</h4>");
        emailMessage.append("<ul><li>Open NCs - " + stats.getTotalOpenNonconformities() + "</li>");

        emailMessage.append("<ul>");
        for (CertifiedBodyStatistics stat : getStatistics(stats.getTotalOpenNonconformitiesByAcb())) {
            emailMessage.append("<li>Certified by ");
            emailMessage.append(stat.getName());
            emailMessage.append(" - ");
            emailMessage.append(stat.getTotalListings().toString());
            emailMessage.append("</li>");
        }
        emailMessage.append("</ul>");

        emailMessage.append("<li>Closed NCs - " + stats.getTotalClosedNonconformities() + "</li></ul>");
        return emailMessage.toString();
    }

    private String createMessageHeader(final Date endDate) {
        Calendar currDateCal = Calendar.getInstance(TimeZone.getTimeZone(ZoneOffset.UTC));
        Calendar endDateCal = Calendar.getInstance(TimeZone.getTimeZone(ZoneOffset.UTC));
        endDateCal.setTime(endDate);
        StringBuilder ret = new StringBuilder();
        ret.append("Email body has current statistics as of " + currDateCal.getTime());
        ret.append("<br/>");
        ret.append("Email attachment has weekly statistics ending " + endDateCal.getTime());
        return ret.toString();
    }

    private String createUniqueDeveloperSection(final Statistics stats) {
        StringBuilder ret = new StringBuilder();

        ret.append(
                "<h4>Total # of Unique Developers (Regardless of Edition) -  " + stats.getTotalDevelopers() + "</h4>");

        ret.append("<ul>");

        ret.append("<li>Total # of Developers with 2014 Listings (Regardless of Status) - "
                + stats.getTotalDevelopersWith2014Listings() + "</li>");
        ret.append("<ul>");
        for (CertifiedBodyStatistics stat : getStatisticsByEdition(
                stats.getTotalDevelopersByCertifiedBodyWithListingsEachYear(), EDITION2014)) {
            ret.append("<li>Certified by ");
            ret.append(stat.getName());
            ret.append(" - ");
            ret.append(stat.getTotalDevelopersWithListings());
        }
        ret.append("</ul>");

        ret.append("<li>Total # of Developers with Active 2014 Listings - "
                + stats.getTotalDevelopersWithActive2014Listings() + "</li>");
        ret.append("<ul>");

        for (CertifiedBodyStatistics stat : getStatisticsByStatusAndEdition(
                stats.getTotalDevsByCertifiedBodyWithListingsInEachCertificationStatusAndYear(), "Active",
                EDITION2014)) {
            ret.append("<li>Certified by ");
            ret.append(stat.getName());
            ret.append(" - ");
            ret.append(stat.getTotalDevelopersWithListings());
        }
        ret.append("</ul>");

        // Calculate 'Total # of Developers with Suspended by ONC-ACB/Suspended by ONC 2014 Listings'
        StringBuilder suspendedDevs2014 = new StringBuilder();
        Long suspendedDevsTotal = 0L;
        for (CertifiedBodyStatistics stat : getStatisticsByStatusAndEdition(
                stats.getTotalDevsByCertifiedBodyWithListingsInEachCertificationStatusAndYear(), "Suspended",
                EDITION2014)) {
            suspendedDevs2014.append("<li>Certified by ");
            suspendedDevs2014.append(stat.getName());
            suspendedDevs2014.append(" - ");
            suspendedDevs2014.append(stat.getTotalDevelopersWithListings());

            suspendedDevsTotal += stat.getTotalDevelopersWithListings();
        }
        // Build the section...
        ret.append("<li>");
        ret.append("Total # of Developers with Suspended by ONC-ACB/Suspended by ONC 2014 Listings - ");
        ret.append(suspendedDevsTotal);
        ret.append("</li>");
        ret.append("<ul>");
        ret.append(suspendedDevs2014.toString());
        ret.append("</ul>");

        ret.append("<li>Total # of Developers with 2015 Listings (Regardless of Status) - "
                + stats.getTotalDevelopersWith2015Listings() + "</li>");
        ret.append("<ul>");
        for (CertifiedBodyStatistics stat : getStatisticsByEdition(
                stats.getTotalDevelopersByCertifiedBodyWithListingsEachYear(), EDITION2015)) {
            ret.append("<li>Certified by ");
            ret.append(stat.getName());
            ret.append(" - ");
            ret.append(stat.getTotalDevelopersWithListings());
        }
        ret.append("</ul>");

        ret.append("<li>Total # of Developers with Active 2015 Listings - "
                + stats.getTotalDevelopersWithActive2015Listings() + "</li>");
        ret.append("<ul>");
        for (CertifiedBodyStatistics stat : getStatisticsByStatusAndEdition(
                stats.getTotalDevsByCertifiedBodyWithListingsInEachCertificationStatusAndYear(), "Active",
                EDITION2015)) {
            ret.append("<li>Certified by ");
            ret.append(stat.getName());
            ret.append(" - ");
            ret.append(stat.getTotalDevelopersWithListings());
        }

        ret.append("</ul>");

        StringBuilder suspendedDevs2015 = new StringBuilder();
        Long suspendedDevsTotal2015 = 0L;
        for (CertifiedBodyStatistics stat : getStatisticsByStatusAndEdition(
                stats.getTotalDevsByCertifiedBodyWithListingsInEachCertificationStatusAndYear(), "Suspended",
                EDITION2015)) {
            suspendedDevs2015.append("<li>Certified by ");
            suspendedDevs2015.append(stat.getName());
            suspendedDevs2015.append(" - ");
            suspendedDevs2015.append(stat.getTotalDevelopersWithListings());

            suspendedDevsTotal2015 += stat.getTotalDevelopersWithListings();
        }

        // Build the section...
        ret.append("<li>");
        ret.append("Total # of Developers with Suspended by ONC-ACB/Suspended by ONC 2015 Listings - ");
        ret.append(suspendedDevsTotal2015);
        ret.append("</li>");
        ret.append("<ul>");
        ret.append(suspendedDevs2015.toString());
        ret.append("</ul>");

        ret.append("</ul>");
        return ret.toString();
    }

    private String createUniqueProductSection(final Statistics stats) {
        StringBuilder ret = new StringBuilder();

        ret.append("<h4>Total # of Certified Unique Products Regardless of Status or Edition - Including 2011) - ");
        ret.append(stats.getTotalCertifiedProducts());
        ret.append("</h4>");

        ret.append("<ul>");
        ret.append("<li>Total # of Unique Products with 2014 Listings (Regardless of Status) -  ");
        ret.append(stats.getTotalCPs2014Listings());
        ret.append("</li>");
        ret.append("<ul>");
        for (CertifiedBodyStatistics cbStat : getStatisticsByEdition(stats.getTotalCPListingsEachYearByCertifiedBody(),
                EDITION2014)) {
            ret.append("<li>Certified by ");
            ret.append(cbStat.getName());
            ret.append(" - ");
            ret.append(cbStat.getTotalListings());
            ret.append("</li>");
        }
        ret.append("</ul>");

        ret.append("<li>Total # of Unique Products with Active 2014 Listings - ");
        ret.append(stats.getTotalCPsActive2014Listings());
        ret.append("</li>");
        ret.append("<ul>");
        for (CertifiedBodyStatistics cbStat : getStatisticsByStatusAndEdition(
                stats.getTotalCPListingsEachYearByCertifiedBodyAndCertificationStatus(), "Active", EDITION2014)) {
            ret.append("<li>Certified by ");
            ret.append(cbStat.getName());
            ret.append(" - ");
            ret.append(cbStat.getTotalListings());
            ret.append("</li>");
        }
        ret.append("</ul>");

        ret.append("<li>Total # of Unique Products with Suspended by ONC-ACB/Suspended by ONC 2014 Listings -  ");
        ret.append(stats.getTotalCPsSuspended2014Listings());
        ret.append("</li>");
        ret.append("<ul>");
        for (CertifiedBodyStatistics cbStat : getStatisticsByStatusAndEdition(
                stats.getTotalCPListingsEachYearByCertifiedBodyAndCertificationStatus(), "Suspended", EDITION2014)) {
            ret.append("<li>Certified by ");
            ret.append(cbStat.getName());
            ret.append(" - ");
            ret.append(cbStat.getTotalListings());
        }
        ret.append("</ul>");

        ret.append("<li>Total # of Unique Products with 2015 Listings (Regardless of Status) -  ");
        ret.append(stats.getTotalCPs2015Listings());
        ret.append("</li>");
        ret.append("<ul>");
        for (CertifiedBodyStatistics cbStat : getStatisticsByEdition(stats.getTotalCPListingsEachYearByCertifiedBody(),
                EDITION2015)) {
            ret.append("<li>Certified by ");
            ret.append(cbStat.getName());
            ret.append(" - ");
            ret.append(cbStat.getTotalListings());
            ret.append("</li>");
        }
        ret.append("</ul>");

        ret.append("<li>Total # of Unique Products with Active 2015 Listings - ");
        ret.append(stats.getTotalCPsActive2015Listings());
        ret.append("</li>");
        ret.append("<ul>");
        for (CertifiedBodyStatistics cbStat : getStatisticsByStatusAndEdition(
                stats.getTotalCPListingsEachYearByCertifiedBodyAndCertificationStatus(), "Active", EDITION2015)) {
            ret.append("<li>Certified by ");
            ret.append(cbStat.getName());
            ret.append(" - ");
            ret.append(cbStat.getTotalListings());
            ret.append("</li>");
        }
        ret.append("</ul>");

        ret.append("<li>Total # of Unique Products with Suspended by ONC-ACB/Suspended by ONC 2015 Listings -  ");
        ret.append(stats.getTotalCPsSuspended2015Listings());
        ret.append("</li>");
        ret.append("<ul>");
        for (CertifiedBodyStatistics cbStat : getStatisticsByStatusAndEdition(
                stats.getTotalCPListingsEachYearByCertifiedBodyAndCertificationStatus(), "Suspended", EDITION2015)) {
            ret.append("<li>Certified by ");
            ret.append(cbStat.getName());
            ret.append(" - ");
            ret.append(cbStat.getTotalListings());
        }
        ret.append("</ul>");

        ret.append("<li>Total # of Unique Products with Active Listings (Regardless of Edition) - "
                + stats.getTotalCPsActiveListings() + "</ul></li>");
        ret.append("</ul>");
        return ret.toString();
    }

    private String createListingSection(final Statistics stats) {
        StringBuilder ret = new StringBuilder();

        ret.append("<h4>Total # of Listings (Regardless of Status or Edition) -  ");
        ret.append(stats.getTotalListings());
        ret.append("</h4>");

        ret.append("<ul>");

        ret.append("<li>Total # of Active (Including Suspended by ONC/ONC-ACB 2014 Listings) - ");
        ret.append(stats.getTotalActive2014Listings());
        ret.append("</li>");
        ret.append("<ul>");
        for (CertifiedBodyStatistics cbStat : getStatisticsByEdition(stats.getTotalActiveListingsByCertifiedBody(),
                EDITION2014)) {
            ret.append("<li>Certified by ");
            ret.append(cbStat.getName());
            ret.append(" - ");
            ret.append(cbStat.getTotalListings());
            ret.append("</li>");
        }
        ret.append("</ul>");

        ret.append("<li>Total # of Active (Including Suspended by ONC/ONC-ACB 2015 Listings) - ");
        ret.append(stats.getTotalActive2015Listings());
        ret.append("</li>");
        ret.append("<ul>");
        for (CertifiedBodyStatistics cbStat : getStatisticsByEdition(stats.getTotalActiveListingsByCertifiedBody(),
                EDITION2015)) {
            ret.append("<li>Certified by ");
            ret.append(cbStat.getName());
            ret.append(" - ");
            ret.append(cbStat.getTotalListings());
            ret.append("</li>");
        }
        ret.append("</ul>");

        ret.append("<li>Total # of 2015 Listings with Alternative Test Methods -  "
                + stats.getTotalListingsWithAlternativeTestMethods() + "</li>");
        ret.append("<ul>");
        for (CertifiedBodyAltTestStatistics cbStat : getStatisticsWithAltTestMethods(stats)) {
            ret.append("<li>Certified by ");
            ret.append(cbStat.getName());
            ret.append(" - ");
            ret.append(cbStat.getTotalListings());
            ret.append("</li>");
        }
        ret.append("</ul>");

        ret.append("<li>Total # of 2014 Listings (Regardless of Status) - " + stats.getTotal2014Listings() + "</li>");
        ret.append("<li>Total # of 2015 Listings (Regardless of Status) - " + stats.getTotal2015Listings() + "</li>");
        ret.append(
                "<li>Total # of 2011 Listings (Regardless of Status) - " + stats.getTotal2011Listings() + "</li></ul>");
        return ret.toString();

    }

    private List<CertifiedBodyStatistics> getStatistics(final List<CertifiedBodyStatistics> stats) {
        List<CertifiedBodyStatistics> acbStats = new ArrayList<CertifiedBodyStatistics>();
        // All the existing stats
        for (CertifiedBodyStatistics cbStat : stats) {
            acbStats.add(cbStat);
        }
        addMissingAcbStatistics(acbStats, null);
        return acbStats;
    }

    private List<CertifiedBodyStatistics> getStatisticsByStatusAndEdition(final List<CertifiedBodyStatistics> stats,
            final String statusName, final Integer edition) {

        List<CertifiedBodyStatistics> acbStats = new ArrayList<CertifiedBodyStatistics>();
        // Filter the existing stats
        for (CertifiedBodyStatistics cbStat : stats) {
            if (cbStat.getYear().equals(edition)
                    && cbStat.getCertificationStatusName().toLowerCase().contains(statusName.toLowerCase())) {
                acbStats.add(cbStat);
            }
        }
        addMissingAcbStatistics(acbStats, edition);
        return acbStats;
    }

    private List<CertifiedBodyStatistics> getStatisticsByEdition(final List<CertifiedBodyStatistics> stats,
            final Integer edition) {

        List<CertifiedBodyStatistics> acbStats = new ArrayList<CertifiedBodyStatistics>();
        // Filter the existing stats
        for (CertifiedBodyStatistics cbStat : stats) {
            if (cbStat.getYear().equals(edition)) {
                acbStats.add(cbStat);
            }
        }
        addMissingAcbStatistics(acbStats, edition);
        return acbStats;
    }

    // Parameter intentionally not 'final'. This way we don;t have to copy the values passed in to a
    // new list.
    private void addMissingAcbStatistics(List<CertifiedBodyStatistics> acbStats, final Integer edition) {
        // Add statistics for missing active ACBs
        acbStats.addAll(getMissingAcbStats(acbStats, edition));

        Collections.sort(acbStats, new Comparator<CertifiedBodyStatistics>() {
            public int compare(final CertifiedBodyStatistics obj1, final CertifiedBodyStatistics obj2) {
                return obj1.getName().compareTo(obj2.getName());
            }
        });
    }

    private List<CertifiedBodyStatistics> getMissingAcbStats(final List<CertifiedBodyStatistics> statistics,
            final Integer edition) {

        List<CertifiedBodyStatistics> updatedStats = new ArrayList<CertifiedBodyStatistics>();
        // Make sure all active ACBs are in the resultset
        for (CertificationBodyDTO acb : activeAcbs) {
            if (!isAcbInStatistics(acb, statistics)) {
                updatedStats.add(getNewCertifiedBodyStatistic(acb.getName(), edition));
            }
        }
        return updatedStats;
    }

    private Boolean isAcbInStatistics(final CertificationBodyDTO acb, final List<CertifiedBodyStatistics> stats) {
        for (CertifiedBodyStatistics stat : stats) {
            if (stat.getName().equals(acb.getName())) {
                return true;
            }
        }
        return false;
    }

    private CertifiedBodyStatistics getNewCertifiedBodyStatistic(final String acbName, final Integer year) {
        CertifiedBodyStatistics stat = new CertifiedBodyStatistics();
        stat.setName(acbName);
        stat.setTotalDevelopersWithListings(0L);
        stat.setTotalListings(0L);
        stat.setYear(year);
        return stat;
    }

    private List<CertifiedBodyAltTestStatistics> getStatisticsWithAltTestMethods(final Statistics stats) {
        List<CertifiedBodyAltTestStatistics> acbStats = new ArrayList<CertifiedBodyAltTestStatistics>();
        // Filter the existing stats
        for (CertifiedBodyAltTestStatistics cbStat : stats
                .getTotalListingsWithCertifiedBodyAndAlternativeTestMethods()) {

            acbStats.add(cbStat);
        }
        // Add statistics for missing active ACBs
        acbStats.addAll(getMissingAcbWithAltTestMethodsStats(acbStats));

        Collections.sort(acbStats, new Comparator<CertifiedBodyAltTestStatistics>() {
            public int compare(final CertifiedBodyAltTestStatistics obj1, final CertifiedBodyAltTestStatistics obj2) {
                return obj1.getName().compareTo(obj2.getName());
            }
        });

        return acbStats;
    }

    private List<CertifiedBodyAltTestStatistics> getMissingAcbWithAltTestMethodsStats(
            final List<CertifiedBodyAltTestStatistics> statistics) {

        List<CertifiedBodyAltTestStatistics> updatedStats = new ArrayList<CertifiedBodyAltTestStatistics>();
        // Make sure all active ACBs are in the resultset
        for (CertificationBodyDTO acb : activeAcbs) {
            if (!isAcbWithAltTestMethodsInStatistics(acb, statistics)) {
                updatedStats.add(getNewCertifiedBodyWithAltTestMethodsStatistic(acb.getName()));
            }
        }
        return updatedStats;
    }

    private CertifiedBodyAltTestStatistics getNewCertifiedBodyWithAltTestMethodsStatistic(final String acbName) {
        CertifiedBodyAltTestStatistics stat = new CertifiedBodyAltTestStatistics();
        stat.setName(acbName);
        stat.setTotalDevelopersWithListings(0L);
        stat.setTotalListings(0L);
        return stat;
    }

    private Boolean isAcbWithAltTestMethodsInStatistics(final CertificationBodyDTO acb,
            final List<CertifiedBodyAltTestStatistics> stats) {

        for (CertifiedBodyAltTestStatistics stat : stats) {
            if (stat.getName().equals(acb.getName())) {
                return true;
            }
        }
        return false;
    }

    private Properties loadProperties() throws IOException {
        InputStream in = SummaryStatisticsCreatorJob.class.getClassLoader()
                .getResourceAsStream(DEFAULT_PROPERTIES_FILE);
        if (in == null) {
            props = null;
            throw new FileNotFoundException("Environment Properties File not found in class path.");
        } else {
            props = new Properties();
            props.load(in);
            in.close();
        }
        return props;
    }
}
