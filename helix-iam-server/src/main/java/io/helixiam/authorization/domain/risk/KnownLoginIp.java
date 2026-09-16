package io.helixiam.authorization.domain.risk;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import java.time.Instant;

/**
 * Helix IAM (adaptive auth): an IP/network the user has successfully authenticated from before.
 * One row per (realm, user, ip); {@code lastSeen} is refreshed on every successful login so the
 * "known IP" risk signal stays current. Optional best-effort geo (country code) is stored when
 * derivable, for the impossible-travel signal.
 *
 * <p>Flat-column JPA entity in its own {@code risk_known_ip} table.
 */
@Entity
@Table(name = "risk_known_ip",
        uniqueConstraints = @UniqueConstraint(
                name = "uq_risk_known_ip", columnNames = {"realm_id", "user_id", "ip"}))
public class KnownLoginIp {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false)
    private String id;

    @Column(name = "realm_id", nullable = false)
    private String realmId;

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name = "ip", nullable = false)
    private String ip;

    /** Best-effort ISO country code derived from the IP; null when no geo source is available. */
    @Column(name = "country")
    private String country;

    @Column(name = "first_seen")
    private Instant firstSeen;

    @Column(name = "last_seen")
    private Instant lastSeen;

    public KnownLoginIp() {
    }

    public KnownLoginIp(final String realmId, final String userId, final String ip) {
        this.realmId = realmId;
        this.userId = userId;
        this.ip = ip;
    }

    public String getId() {
        return id;
    }

    public void setId(final String id) {
        this.id = id;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(final String realmId) {
        this.realmId = realmId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(final String userId) {
        this.userId = userId;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(final String ip) {
        this.ip = ip;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(final String country) {
        this.country = country;
    }

    public Instant getFirstSeen() {
        return firstSeen;
    }

    public void setFirstSeen(final Instant firstSeen) {
        this.firstSeen = firstSeen;
    }

    public Instant getLastSeen() {
        return lastSeen;
    }

    public void setLastSeen(final Instant lastSeen) {
        this.lastSeen = lastSeen;
    }
}
