package bot.inker.keycloak.cidr;

import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public final class CidrAuthenticator implements Authenticator {
  private static final String CONNECTION_NOT_FOUND_MESSAGE = "only support browser flow";
  private static final String IP_NOT_ALLOWED_MESSAGE = "ip not allowed";
  private final CidrAuthenticatorConfig config;

  public CidrAuthenticator(CidrAuthenticatorConfig config) {
    this.config = config;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    final var connection = context.getConnection();
    if(connection == null) {
      responseEnd(context, CONNECTION_NOT_FOUND_MESSAGE);
      return;
    }
    final var address = connection.getRemoteAddr();
    if(connection == null) {
      responseEnd(context, CONNECTION_NOT_FOUND_MESSAGE);
      return;
    }
    if (config.isAllow(address)) {
      context.success();
    }else{
      responseEnd(context, IP_NOT_ALLOWED_MESSAGE);
    }
  }

  private static void responseEnd(AuthenticationFlowContext context, String userErrorMessage) {
    context.getEvent().error(Errors.ACCESS_DENIED);
    Response challenge = context.form()
        .setError(userErrorMessage)
        .createErrorPage(Response.Status.UNAUTHORIZED);
    context.failure(AuthenticationFlowError.ACCESS_DENIED, challenge);
  }

  @Override
  public void action(AuthenticationFlowContext context) {

  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return false;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

  }

  @Override
  public void close() {

  }
}
