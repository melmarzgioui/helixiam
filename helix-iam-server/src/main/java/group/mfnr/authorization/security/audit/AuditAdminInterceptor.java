package group.mfnr.authorization.security.audit;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Set;

/**
 * Helix IAM E8.5-S4 (Events): emits an ADMIN audit event for every mutating {@code /admin/**} request,
 * once it completes, with zero per-controller code. The event type/resource is derived from the request
 * by {@link AuditEventMapper}; the actor and source IP come from {@link AuditContext}; the outcome from
 * the response status. Reads (GET/HEAD/OPTIONS) are not audited — only state changes.
 */
@Component
public class AuditAdminInterceptor implements HandlerInterceptor {

    private static final Set<String> MUTATING = Set.of("POST", "PUT", "PATCH", "DELETE");

    private final AuditLog auditLog;

    public AuditAdminInterceptor(final AuditLog auditLog) {
        this.auditLog = auditLog;
    }

    @Override
    public void afterCompletion(final HttpServletRequest request, final HttpServletResponse response,
                                final Object handler, final Exception ex) {
        if (!MUTATING.contains(request.getMethod().toUpperCase())) {
            return;
        }
        final int status = ex != null && response.getStatus() < 400 ? 500 : response.getStatus();
        final AuditEventMapper.AdminAudit a = AuditEventMapper.map(request.getMethod().toUpperCase(),
                request.getRequestURI(), status);
        auditLog.emit(AuditEvent.admin(AuditContext.nowIso(), a.type(), a.realm(), AuditContext.adminActor(),
                AuditContext.clientIp(request), a.resourceType(), a.resourceId(), a.outcome()));
    }
}
