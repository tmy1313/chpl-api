package gov.healthit.chpl.scheduler.job.svapreports;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;

import org.quartz.DisallowConcurrentExecution;
import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import gov.healthit.chpl.dao.statistics.SvapReportDeveloperCountsDAO;
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
public class SvapReportsJob implements Job {
    @Autowired
    private Environment env;

    @Autowired
    private SvapReportDeveloperCountsDAO svapReportDeveloperCountsDao;

    @Override
    public void execute(JobExecutionContext jobContext) throws JobExecutionException {
        SpringBeanAutowiringSupport.processInjectionBasedOnCurrentContext(this);

        try (InputStream svapStream = getClass().getResourceAsStream("/reports/svap.jrxml");
                InputStream svapDevelopersStream = getClass().getResourceAsStream("/reports/svap-developers.jrxml");) {
            JasperDesign svapDesign = JRXmlLoader.load(svapStream);
            JasperReport svapReport = JasperCompileManager.compileReport(svapDesign);
            JasperDesign svapDevelopersDesign = JRXmlLoader.load(svapDevelopersStream);
            JasperReport svapDevelopersReport = JasperCompileManager.compileReport(svapDevelopersDesign);


            List<SvapReportDeveloperCounts> svapDevelopers = getData();
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

    private List<SvapReportDeveloperCounts> getData() {
        return svapReportDeveloperCountsDao.getAll();
    }
}
