package group.mfnr.authorization.controller;

import group.mfnr.authorization.security.audit.AuditContext;
import group.mfnr.authorization.security.audit.AuditEvent;
import group.mfnr.authorization.security.audit.AuditLog;
import group.mfnr.authorization.security.impersonation.ImpersonationService;
import group.mfnr.authorization.security.realm.RealmContextHolder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Helix IAM B4: ends an admin impersonation session. Reachable by the (impersonated) authenticated
 * session — {@code anyRequest().authenticated()} covers it — and invalidates the session so the
 * impersonated identity is fully dropped. Emits an {@code IMPERSONATE_END} audit event naming the admin.
 */
@RestController
public class ImpersonationController {

    private final ImpersonationService impersonationService;
    private final AuditLog auditLog;

    public ImpersonationController(final ImpersonationService impersonationService, final AuditLog auditLog) {
        this.impersonationService = impersonationService;
        this.auditLog = auditLog;
    }

    // GET so it can be a plain "Stop impersonating" link; the exact path wins over the SPA catch-all.
    @GetMapping("/stop-impersonation")
    @PostMapping("/stop-impersonation")
    public void stop(final HttpServletRequest request, final HttpServletResponse response) throws java.io.IOException {
        // Capture the realm + context BEFORE invalidating the session (invalidate may clear the request state).
        final String contextPath = request.getContextPath();
        final String realm = RealmContextHolder.get();
        final String admin = impersonationService.stop(request, response);
        if (admin != null) {
            auditLog.emit(AuditEvent.admin(AuditContext.nowIso(), "IMPERSONATE_END", realm,
                    admin, AuditContext.clientIp(request), "users", null, "SUCCESS"));
        }
        // Session is invalidated; land back on the login page (context-relative to stay under the realm path).
        response.sendRedirect(contextPath + "/login?info=impersonationEnded");
    }
}
