package io.helixiam.authorization.controller.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.helixiam.authorization.amqp.messaging.MessageTemplateDto;
import io.helixiam.authorization.amqp.messaging.MessagingAdminPublisher;
import io.helixiam.authorization.messaging.TemplateRenderer;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM notifications (N2): admin REST API for a realm's message templates — the backend behind the
 * console's Templates editor. {@code GET} seeds + returns the realm's templates; {@code PUT} upserts one;
 * {@code POST /preview} renders a body/subject with sample variables for the live preview.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/messaging/templates")
public class MessageTemplateController {

    private final MessagingAdminPublisher publisher;

    public MessageTemplateController(final MessagingAdminPublisher publisher) {
        this.publisher = publisher;
    }

    @GetMapping
    public List<MessageTemplateDto> list(@PathVariable final String realmId) {
        return publisher.listTemplates(realmId);
    }

    @PutMapping
    public MessageTemplateDto save(@PathVariable final String realmId, @Valid @RequestBody final MessageTemplateDto body) {
        return publisher.saveTemplate(new MessageTemplateDto(body.id(), realmId, body.templateKey(),
                body.channel(), body.subject(), body.body(), body.enabled(), body.html()));
    }

    /** Render a template against caller-supplied (or sample) variables — for the console live preview. */
    @PostMapping("/preview")
    public Rendered preview(@PathVariable final String realmId, @RequestBody final PreviewRequest request) {
        final Map<String, String> vars = request.variables() == null || request.variables().isEmpty()
                ? TemplateRenderer.sampleVariables(realmId) : request.variables();
        return new Rendered(TemplateRenderer.render(request.subject(), vars),
                TemplateRenderer.render(request.body(), vars));
    }

    /** Preview request: the unsaved subject/body + optional variable overrides. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PreviewRequest(String subject, String body, Map<String, String> variables) {
    }

    /** Preview result: the rendered subject + body. */
    public record Rendered(String subject, String body) {
    }
}
