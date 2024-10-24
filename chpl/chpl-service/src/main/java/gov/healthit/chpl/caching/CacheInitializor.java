package gov.healthit.chpl.caching;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.Future;

import javax.annotation.PostConstruct;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import gov.healthit.chpl.exception.EntityRetrievalException;
import net.sf.ehcache.CacheManager;

@Component
@Aspect
public class CacheInitializor {
    private static final Logger LOGGER = LogManager.getLogger(CacheInitializor.class);
    private static final String DEFAULT_PROPERTIES_FILE = "environment.properties";
    private Integer initializeTimeoutSecs;
    private Long tInitStart;
    private Long tInitEnd;
    private Double tInitElapsedSecs;
    private Future<Boolean> isInitializeSearchOptionsDone;
    private Future<Boolean> isInitializeBasicSearch;
    private Future<Boolean> isInitializeCertificationIdsGetAllDone;
    private Future<Boolean> isInitializeCertificationIdsGetAllWithProductsDone;
    private Properties props;
    private String enableCacheInitializationValue;

    @Autowired
    private AsynchronousCacheInitialization asynchronousCacheInitialization;

    public static List<String> getPreInitializedCaches() {
        List<String> caches = new ArrayList<String>();
        caches.add(CacheNames.COLLECTIONS_LISTINGS);
        caches.add(CacheNames.ALL_CERT_IDS);
        caches.add(CacheNames.ALL_CERT_IDS_WITH_PRODUCTS);
        //all below caches make up the search options
        caches.add(CacheNames.EDITION_NAMES);
        caches.add(CacheNames.CERTIFICATION_STATUSES);
        caches.add(CacheNames.PRACTICE_TYPE_NAMES);
        caches.add(CacheNames.CLASSIFICATION_NAMES);
        caches.add(CacheNames.PRODUCT_NAMES);
        caches.add(CacheNames.DEVELOPER_NAMES);
        caches.add(CacheNames.CQM_CRITERION_NUMBERS);
        caches.add(CacheNames.CERTIFICATION_CRITERION_NUMBERS);
        return caches;
    }

    @PostConstruct
    @Async
    public void initialize() throws IOException, EntityRetrievalException, InterruptedException {
        if (props == null) {
            InputStream in = CacheInitializor.class.getClassLoader().getResourceAsStream(DEFAULT_PROPERTIES_FILE);

            if (in == null) {
                props = null;
                throw new FileNotFoundException("Environment Properties File not found in class path.");
            } else {
                props = new Properties();
                props.load(in);
                in.close();
            }

            enableCacheInitializationValue = props.getProperty("enableCacheInitialization");
            initializeTimeoutSecs = Integer.parseInt(props.getProperty("cacheInitializeTimeoutSecs").toString());
        }

        tInitStart = System.currentTimeMillis();
        if (tInitEnd != null) {
            tInitElapsedSecs = (tInitStart - tInitEnd) / 1000.0;
        }

        if (tInitEnd == null || tInitElapsedSecs > initializeTimeoutSecs) {
            try {
                if (enableCacheInitializationValue != null && enableCacheInitializationValue.equalsIgnoreCase("true")) {
                    if (isInitializeSearchOptionsDone != null && !isInitializeSearchOptionsDone.isDone()) {
                        isInitializeSearchOptionsDone.cancel(true);
                    }
                    isInitializeSearchOptionsDone = asynchronousCacheInitialization.initializeSearchOptions();
                    if (isInitializeCertificationIdsGetAllDone != null
                            && !isInitializeCertificationIdsGetAllDone.isDone()) {
                        isInitializeCertificationIdsGetAllDone.cancel(true);
                    }
                    isInitializeCertificationIdsGetAllDone = asynchronousCacheInitialization
                            .initializeCertificationIdsGetAll();

                    if (isInitializeCertificationIdsGetAllWithProductsDone != null
                            && !isInitializeCertificationIdsGetAllWithProductsDone.isDone()) {
                        isInitializeCertificationIdsGetAllWithProductsDone.cancel(true);
                    }
                    isInitializeCertificationIdsGetAllWithProductsDone = asynchronousCacheInitialization
                            .initializeCertificationIdsGetAllWithProducts();

                    if (isInitializeBasicSearch != null && !isInitializeBasicSearch.isDone()) {
                        isInitializeBasicSearch.cancel(true);
                    }
                    isInitializeBasicSearch = asynchronousCacheInitialization.initializeBasicSearch();
                }
            } catch (Exception e) {
                System.out.println("Caching failed to initialize");
                e.printStackTrace();
            }
        }
        tInitEnd = System.currentTimeMillis();
    }
}
