package gov.healthit.chpl.scheduler.job;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.quartz.DisallowConcurrentExecution;
import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import lombok.extern.log4j.Log4j2;
import net.sf.jasperreports.engine.JRException;
import net.sf.jasperreports.engine.JasperCompileManager;
import net.sf.jasperreports.engine.JasperExportManager;
import net.sf.jasperreports.engine.JasperFillManager;
import net.sf.jasperreports.engine.JasperPrint;
import net.sf.jasperreports.engine.JasperReport;
import net.sf.jasperreports.engine.data.JRBeanCollectionDataSource;
import net.sf.jasperreports.engine.design.JasperDesign;
import net.sf.jasperreports.engine.xml.JRXmlLoader;

@DisallowConcurrentExecution
@Log4j2
public class SvapReportJob implements Job {
    @Autowired
    private Environment env;

    @Override
    public void execute(JobExecutionContext jobContext) throws JobExecutionException {
        SpringBeanAutowiringSupport.processInjectionBasedOnCurrentContext(this);

        try (InputStream svapStream = getClass().getResourceAsStream("/reports/svap.jrxml");
                InputStream svapDevelopersStream = getClass().getResourceAsStream("/reports/svap-developers.jrxml");) {
            JasperDesign svapDesign = JRXmlLoader.load(svapStream);
            JasperReport svapReport = JasperCompileManager.compileReport(svapDesign);
            JasperDesign svapDevelopersDesign = JRXmlLoader.load(svapDevelopersStream);
            JasperReport svapDevelopersReport = JasperCompileManager.compileReport(svapDevelopersDesign);


            List<SvapDeveloperCounts> svapDevelopers = getData();
            JRBeanCollectionDataSource developersWithStatsDataSource = new JRBeanCollectionDataSource(svapDevelopers);

            HashMap<String, Object> parameters = new HashMap<String, Object>();
            parameters.put("developersWithStatsDataSource", developersWithStatsDataSource);
            parameters.put("developersWithStatsReport", svapDevelopersReport);

            JasperPrint jasperPrint = JasperFillManager.fillReport(svapReport, parameters, developersWithStatsDataSource);
            JasperExportManager.exportReportToPdfFile(jasperPrint, env.getProperty("downloadFolderPath") + "\\test_jasper.pdf");
        } catch (JRException | IOException ex) {
            LOGGER.catching(ex);
        }
    }

    private List<SvapDeveloperCounts> getData() {
        return new ArrayList<SvapDeveloperCounts>(
                Arrays.asList(
                    new SvapDeveloperCounts("Office Practicum", "Drummond Group", 2, 3, 4),
                    new SvapDeveloperCounts("Ulrich Medical Concepts", "Drummond Group", 2, 3, 4),
                    new SvapDeveloperCounts("PHI Medical Office Solutions", "Drummond Group", 2, 3, 4),
                    new SvapDeveloperCounts("EyeCare Partners, LLC", "Drummond Group", 2, 3, 4),
                    new SvapDeveloperCounts("Sapphire Health", "Drummond Group", 2, 3, 4),
                    new SvapDeveloperCounts("Rhinogram, LLC", "Drummond Group", 2, 3, 4),
                    new SvapDeveloperCounts("Payoda Technology Inc.", "Drummond Group", 2, 3, 4),
                    new SvapDeveloperCounts("Skilled Wound Care", "Drummond Group", 2, 3, 4),
                    new SvapDeveloperCounts("PRN Software (DoseSpot)", "Drummond Group", 2, 3, 4),
                    new SvapDeveloperCounts("Medicus Clinical, LLC", "Drummond Group", 2, 3, 4),
                    new SvapDeveloperCounts("Lille Group, Inc.", "Drummond Group", 2, 3, 4),
                    new SvapDeveloperCounts("mdTimeline, LLC", "Drummond Group", 2, 3, 4),
                    new SvapDeveloperCounts("DocToMe, Inc.", "Drummond Group", 2, 3, 4),
                    new SvapDeveloperCounts("DB Consultants, Inc.", "Drummond Group", 2, 3, 4),
                    new SvapDeveloperCounts("Radiologex", "Drummond Group", 2, 3, 4),
                    new SvapDeveloperCounts("Viviphi Ltd", "Drummond Group", 2, 3, 4),
                    new SvapDeveloperCounts("Softbir, Inc.", "SLI Compliance", 2, 3, 4),
                    new SvapDeveloperCounts("Accelerated Care Plus", "SLI Compliance", 2, 3, 4),
                    new SvapDeveloperCounts("GE Healthcare", "SLI Compliance", 2, 3, 4),
                    new SvapDeveloperCounts("Picis PulseCheck, a business unit of Harris Computer Systems", "SLI Compliance", 2, 3, 4),
                    new SvapDeveloperCounts("CloudCraft, LLC", "SLI Compliance", 2, 3, 4),
                    new SvapDeveloperCounts("OmniLife, Inc.", "SLI Compliance", 2, 3, 4),
                    new SvapDeveloperCounts("Mediportal, LLC", "SLI Compliance", 2, 3, 4),
                    new SvapDeveloperCounts("Apervita Inc.", "SLI Compliance", 2, 3, 4),
                    new SvapDeveloperCounts("R1 RCM", "UL LLC", 2, 3, 4),
                    new SvapDeveloperCounts("ZH Healthcare, Inc.", "UL LLC", 2, 3, 4),
                    new SvapDeveloperCounts("JVM, Co., Ltd.", "UL LLC", 2, 3, 4),
                    new SvapDeveloperCounts("KPI Ninja", "UL LLC", 2, 3, 4),
                    new SvapDeveloperCounts("YOURDRS Services LLC", "UL LLC", 2, 3, 4),
                    new SvapDeveloperCounts("MDinteractive", "UL LLC", 2, 3, 4),
                    new SvapDeveloperCounts("Healthfully Inc.", "ICSA Labs", 2, 3, 4),
                    new SvapDeveloperCounts("MphRx", "ICSA Labs", 2, 3, 4),
                    new SvapDeveloperCounts("Iora Health", "ICSA Labs", 2, 3, 4),
                    new SvapDeveloperCounts("Landmark Health, LLC", "ICSA Labs", 2, 3, 4)));
    }
}
