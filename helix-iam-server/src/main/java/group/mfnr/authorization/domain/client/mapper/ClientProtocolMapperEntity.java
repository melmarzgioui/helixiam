package group.mfnr.authorization.domain.client.mapper;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.sql.Timestamp;

/** Helix IAM (Wave 3): a per-client protocol mapper (subscriber-owned). */
@Entity
@Table(name = "client_protocol_mapper")
public class ClientProtocolMapperEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "mapper_id", updatable = false)
    private String mapperId;

    @Column(name = "realm_id")
    private String realmId = "master";

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "name")
    private String name;

    @Column(name = "mapper_type")
    private String mapperType;

    @Column(name = "source")
    private String source;

    @Column(name = "claim_name")
    private String claimName;

    @Column(name = "add_to_access_token")
    private Boolean addToAccessToken = true;

    @Column(name = "add_to_id_token")
    private Boolean addToIdToken = true;

    @Column(name = "creation_date", updatable = false)
    private Timestamp creationDate = new Timestamp(System.currentTimeMillis());

    public String getMapperId() { return mapperId; }
    public void setMapperId(final String v) { this.mapperId = v; }
    public String getRealmId() { return realmId; }
    public void setRealmId(final String v) { this.realmId = v; }
    public String getClientId() { return clientId; }
    public void setClientId(final String v) { this.clientId = v; }
    public String getName() { return name; }
    public void setName(final String v) { this.name = v; }
    public String getMapperType() { return mapperType; }
    public void setMapperType(final String v) { this.mapperType = v; }
    public String getSource() { return source; }
    public void setSource(final String v) { this.source = v; }
    public String getClaimName() { return claimName; }
    public void setClaimName(final String v) { this.claimName = v; }
    public Boolean getAddToAccessToken() { return addToAccessToken; }
    public void setAddToAccessToken(final Boolean v) { this.addToAccessToken = v; }
    public Boolean getAddToIdToken() { return addToIdToken; }
    public void setAddToIdToken(final Boolean v) { this.addToIdToken = v; }
}
