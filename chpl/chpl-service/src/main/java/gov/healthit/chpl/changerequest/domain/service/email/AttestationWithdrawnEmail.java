package gov.healthit.chpl.changerequest.domain.service.email;

import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import gov.healthit.chpl.changerequest.domain.ChangeRequest;
import gov.healthit.chpl.changerequest.domain.ChangeRequestAttestationSubmission;
import gov.healthit.chpl.dao.DeveloperDAO;
import gov.healthit.chpl.email.ChplEmailFactory;
import gov.healthit.chpl.email.ChplHtmlEmailBuilder;
import gov.healthit.chpl.email.footer.PublicFooter;
import gov.healthit.chpl.exception.EmailNotSentException;
import gov.healthit.chpl.permissions.ResourcePermissionsFactory;
import gov.healthit.chpl.util.AuthUtil;

@Component
public class AttestationWithdrawnEmail extends ChangeRequestEmail {
    private ChplEmailFactory chplEmailFactory;
    private ChplHtmlEmailBuilder chplHtmlEmailBuilder;
    private String emailSubject;
    private String emailBody;


    @Autowired
    public AttestationWithdrawnEmail(ChplEmailFactory chplEmailFactory, ChplHtmlEmailBuilder chplHtmlEmailBuilder,
            ResourcePermissionsFactory resourcePermissionsFactory, DeveloperDAO developerDAO,
            @Value("${changeRequest.attestation.withdrawn.subject}") String emailSubject,
            @Value("${changeRequest.attestation.withdrawn.body}") String emailBody) {

        super(resourcePermissionsFactory, developerDAO);
        this.chplEmailFactory = chplEmailFactory;
        this.chplHtmlEmailBuilder = chplHtmlEmailBuilder;
        this.emailSubject = emailSubject;
        this.emailBody = emailBody;
    }

    @Override
    public void send(ChangeRequest cr) throws EmailNotSentException {
        chplEmailFactory.emailBuilder()
            .recipients(getUsersForDeveloper(cr.getDeveloper().getId()).stream()
                    .map(user -> user.getEmail())
                    .collect(Collectors.toList()))
            .subject(emailSubject)
            .htmlMessage(withdrawnUpdatedHtmlMessage(cr))
            .sendEmail();
    }

    private String withdrawnUpdatedHtmlMessage(ChangeRequest cr) {
        return chplHtmlEmailBuilder.initialize()
                .heading("Developer Attestations Withdrawn")
                .paragraph("", String.format(emailBody,
                        cr.getDeveloper().getName(),
                        cr.getSubmittedDateTime().format(DateTimeFormatter.ofLocalizedDate(FormatStyle.SHORT)),
                        AuthUtil.getUsername()))
                .paragraph("Attestation Responses submitted for " + cr.getDeveloper().getName(), toHtmlString((ChangeRequestAttestationSubmission) cr.getDetails(), chplHtmlEmailBuilder))
                .footer(PublicFooter.class)
                .build();
    }
}
