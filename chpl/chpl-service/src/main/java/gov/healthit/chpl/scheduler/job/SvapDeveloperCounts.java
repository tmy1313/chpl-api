package gov.healthit.chpl.scheduler.job;

public class SvapDeveloperCounts {
    private String developerName;
    private String acb;
    private Integer listingCount = 0;
    private Integer criteriaCount = 0;
    private Integer svapCount = 0;

     SvapDeveloperCounts(String developerName, String acb, Integer listingCount, Integer criteriaCount, Integer svapCount) {
        this.developerName = developerName;
        this.acb = acb;
        this.listingCount = listingCount;
        this.criteriaCount = criteriaCount;
        this.svapCount = svapCount;
     }

    public String getDeveloperName() {
        return developerName;
    }
    public void setDeveloperName(String developerName) {
        this.developerName = developerName;
    }

    public String getAcb() {
        return acb;
    }
    public void setAcb(String acb) {
        this.acb = acb;
    }

    public Integer getListingCount() {
        return listingCount;
    }

    public void setListingCount(Integer listingCount) {
        this.listingCount = listingCount;
    }

    public Integer getCriteriaCount() {
        return criteriaCount;
    }

    public void setCriteriaCount(Integer criteriaCount) {
        this.criteriaCount = criteriaCount;
    }

    public Integer getSvapCount() {
        return svapCount;
    }

    public void setSvapCount(Integer svapCount) {
        this.svapCount = svapCount;
    }

}
