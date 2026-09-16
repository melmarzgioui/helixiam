package group.mfnr.authorization.amqp.risk;


/**
 * Helix IAM (adaptive auth): risk-history operations against the subscriber (the owner of the
 * device/IP history) over AMQP — resolve the risk signals for an attempt, and record a successful
 * login so the device + IP become "known".
 *
 * <p><b>Routing-key gotcha:</b> these {@code @AnonymousSender} keys are fully <i>dot</i>-delimited;
 * the matching subscriber {@code @AnonymousListener} keys are <i>dash</i>-delimited
 * ({@code authorization-risk-evaluate-signals} / {@code authorization-risk-record-login}).
 */
public interface RiskPublisher {

    String EXCHANGE_AUTHORIZATION_RISK = "exchange-authorization-risk";
    String RISK_EVALUATE_SIGNALS = "authorization.risk.evaluate.signals";
    String RISK_RECORD_LOGIN = "authorization.risk.record.login";

    RiskSignals evaluateSignals(final RiskSignalRequest request);

    Boolean recordLogin(final RiskLoginRecord record);
}
