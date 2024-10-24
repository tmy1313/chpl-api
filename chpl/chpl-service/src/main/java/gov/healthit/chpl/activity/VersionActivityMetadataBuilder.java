package gov.healthit.chpl.activity;

import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import gov.healthit.chpl.dao.ProductDAO;
import gov.healthit.chpl.domain.activity.ActivityCategory;
import gov.healthit.chpl.domain.activity.ActivityMetadata;
import gov.healthit.chpl.domain.activity.ProductActivityMetadata;
import gov.healthit.chpl.domain.activity.VersionActivityMetadata;
import gov.healthit.chpl.dto.ActivityDTO;
import gov.healthit.chpl.dto.DeveloperDTO;
import gov.healthit.chpl.dto.ProductDTO;
import gov.healthit.chpl.dto.ProductVersionDTO;

@Component("versionActivityMetadataBuilder")
public class VersionActivityMetadataBuilder extends ActivityMetadataBuilder {
    private static final Logger LOGGER = LogManager.getLogger(VersionActivityMetadataBuilder.class);
    private ObjectMapper jsonMapper;
    private ProductDAO productDao;

    @Autowired
    public VersionActivityMetadataBuilder(final ProductDAO productDao) {
        super();
        jsonMapper = new ObjectMapper();
        this.productDao = productDao;
    }

    protected void addConceptSpecificMetadata(final ActivityDTO activity, final ActivityMetadata metadata) {
        if (!(metadata instanceof VersionActivityMetadata)) {
            return;
        }
        VersionActivityMetadata versionMetadata = (VersionActivityMetadata) metadata;

        //parse version specific metadata
        //original data can be a list of versions in the case of version merge
        //otherwise we expect it to be a single ProductVersionDTO.
        ProductVersionDTO origVersion = null;
        List<ProductVersionDTO> origVersions = null;
        if (activity.getOriginalData() != null) {
            try {
                origVersion =
                    jsonMapper.readValue(activity.getOriginalData(), ProductVersionDTO.class);
            } catch (final Exception ignore) { }

            if (origVersion == null) {
                try {
                    origVersions = jsonMapper.readValue(activity.getOriginalData(),
                            jsonMapper.getTypeFactory().constructCollectionType(List.class, ProductVersionDTO.class));
                } catch (Exception ignore) { }
            }

            if (origVersion == null && origVersions == null) {
                LOGGER.error("Could not parse activity ID " + activity.getId() + " original data "
                        + "as ProductVersionDTO or List<ProductVersionDTO>. "
                        + "JSON was: " + activity.getOriginalData());
            }
        }

        ProductVersionDTO newVersion = null;
        List<ProductVersionDTO> newVersions = null;
        if (activity.getNewData() != null) {
            try {
                newVersion =
                    jsonMapper.readValue(activity.getNewData(), ProductVersionDTO.class);
            } catch (final Exception ignore) { }

            if (newVersion == null) {
                try {
                    newVersions = jsonMapper.readValue(activity.getNewData(),
                            jsonMapper.getTypeFactory().constructCollectionType(List.class, ProductVersionDTO.class));
                } catch (Exception ignore) { }
            }

            if (newVersion == null && newVersions == null) {
                LOGGER.error("Could not parse activity ID " + activity.getId() + " new data "
                        + "as ProductVersionDTO or List<ProductVersionDTO>. "
                        + "JSON was: " + activity.getNewData());
            }
        }

        if (newVersion != null && origVersion != null
                && newVersions == null && origVersions == null) {
            //if there is a single new version and single original version
            //that means the activity was editing the version
            parseVersionMetadata(versionMetadata, newVersion);
        } else if (origVersion != null && newVersion == null
                && newVersions == null && origVersions == null) {
            //if there is an original version but no new version
            //then the version was deleted - pull its info from the orig object
            parseVersionMetadata(versionMetadata, origVersion);
        } else if (newVersion != null && origVersion == null
                && newVersions == null && origVersions == null) {
            //if there is a new version but no original version
            //then the version was just created
            parseVersionMetadata(versionMetadata, newVersion);
        } else if (newVersions != null && origVersion != null
                && newVersion == null && origVersions == null) {
            //multiple new versions and a single original version
            //means the activity was a split
            parseVersionMetadata(versionMetadata, activity, newVersions);
        } else if (origVersions != null && newVersion != null
                && origVersion == null && newVersions == null) {
            //multiple original versions and a single new version
            //means the activity was a merge
            parseVersionMetadata(versionMetadata, newVersion);
        }

        versionMetadata.getCategories().add(ActivityCategory.VERSION);
    }

    private void parseVersionMetadata(
            final VersionActivityMetadata versionMetadata, final ProductVersionDTO version) {
        //Product ID or Name may or may not be filled in.
        //Try to get the product name if either is available.
        if (!StringUtils.isEmpty(version.getProductName())) {
            versionMetadata.setProductName(version.getProductName());
        } else if (version.getProductId() != null) {
            try {
                ProductDTO product = productDao.getById(version.getProductId(), true);
                versionMetadata.setProductName(product.getName());
            } catch (Exception ex) {
                LOGGER.error("Unable to find product with ID " + version.getProductId() + " referenced "
                        + "in activity for version " + version.getId());
            }
        }
        versionMetadata.setVersion(version.getVersion());
    }

    private void parseVersionMetadata(
            final VersionActivityMetadata versionMetadata, final ActivityDTO activity,
            final List<ProductVersionDTO> versions) {
        Long idToFind = activity.getActivityObjectId();
        for (ProductVersionDTO currVersion : versions) {
            if(currVersion.getId().longValue() == idToFind.longValue()) {
                parseVersionMetadata(versionMetadata, currVersion);
                break;
            }
        }
    }
}
