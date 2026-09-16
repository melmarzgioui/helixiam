package group.mfnr.authorization.session;

/** The kind of identity behind a session/token, surfaced on the admin Sessions screen. */
public enum IdentityType {
  USER,
  AGENT,
  SERVICE_ACCOUNT,
  WORKLOAD
}
