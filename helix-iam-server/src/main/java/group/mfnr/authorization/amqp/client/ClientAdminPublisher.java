package group.mfnr.authorization.amqp.client;


import java.util.List;

/**
 * Helix IAM E8.5-S3: the Clients admin API's seam onto the client-domain store (owned by the
 * subscriber). Routing keys are single tokens (no hyphens) for unambiguous queue binding.
 */
public interface ClientAdminPublisher {

    String EXCHANGE_AUTHORIZATION_CLIENT_ADMIN = "exchange-authorization-client-admin";
    String CLIENT_ADMIN_LIST = "authorization.client.admin.list";
    String CLIENT_ADMIN_GET = "authorization.client.admin.get";
    String CLIENT_ADMIN_CREATE = "authorization.client.admin.create";
    String CLIENT_ADMIN_UPDATE = "authorization.client.admin.update";
    String CLIENT_ADMIN_DELETE = "authorization.client.admin.delete";
    String CLIENT_ADMIN_REGENERATE = "authorization.client.admin.regenerate";
    String CLIENT_ADMIN_REVEAL = "authorization.client.admin.reveal";

    List<ClientDto> list(final String realmId);

    ClientDto get(final ClientRef ref);

    ClientDto create(final ClientWriteDto write);

    ClientDto update(final ClientWriteDto write);

    Boolean delete(final ClientRef ref);

    ClientDto regenerate(final ClientRef ref);

    ClientDto reveal(final ClientRef ref);
}
