package group.mfnr.authorization.amqp.account.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import group.mfnr.authorization.amqp.account.AccountIdentityPublisher;
import group.mfnr.authorization.amqp.account.AccountUnlinkRef;
import group.mfnr.authorization.amqp.account.FederatedLinkDto;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.service.federation.FederatedLinkService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter that replaces the former AMQP transport of
 * {@link AccountIdentityPublisher}, delegating directly to the domain service.
 */
@Component
public class AccountIdentityLocalAdapter implements AccountIdentityPublisher {

    private final FederatedLinkService links;
    private final DtoBridge bridge;

    public AccountIdentityLocalAdapter(final FederatedLinkService links, final DtoBridge bridge) {
        this.links = links;
        this.bridge = bridge;
    }

    @Override
    public List<FederatedLinkDto> list(final String userId) {
        return bridge.to(links.linksForUser(userId), new TypeReference<List<FederatedLinkDto>>() { });
    }

    @Override
    public Boolean unlink(final AccountUnlinkRef ref) {
        return links.unlink(ref.userId(), ref.idpAlias());
    }
}
