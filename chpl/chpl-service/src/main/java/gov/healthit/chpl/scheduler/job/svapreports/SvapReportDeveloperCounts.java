package gov.healthit.chpl.scheduler.job.svapreports;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SvapReportDeveloperCounts {
    private Long id;
    private Long developerId;
    private String developerName;
    private Long certificationBodyId;
    private String acb;
    private Integer listingCount;
    private Integer criteriaCount;
    private Integer svapCount;

}
