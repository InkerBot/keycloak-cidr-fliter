package bot.inker.keycloak.cidr;

import jakarta.ws.rs.core.Response;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.keycloak.Config;
import org.keycloak.authentication.*;
import org.keycloak.events.Errors;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

public final class CidrAuthenticatorFactory implements AuthenticatorFactory, Authenticator, ConfigurableAuthenticatorFactory {
  private static final String IDENTIFY = "cidr-authenticator";
  private static final String KEY_DEFAULT_ALLOW = "default-allow";
  private static final String KEY_RULE_LIST = "rule-list";
  private static final String KEY_DENY_MESSAGE = "deny-message";

  private static final String CONNECTION_NOT_FOUND_MESSAGE = "only support browser flow";
  private static final String DEFAULT_DENY_MESSAGE = "ip not allowed";

  private static final List<ProviderConfigProperty> PROPERTY_LIST = Arrays.asList(
      new ProviderConfigProperty(
          KEY_DEFAULT_ALLOW,
          "default-allow",
          "default allow",
          ProviderConfigProperty.BOOLEAN_TYPE,
          true
      ), new ProviderConfigProperty(
          KEY_RULE_LIST,
          "rule-list",
          "rule list",
          ProviderConfigProperty.MULTIVALUED_STRING_TYPE,
          new String[0]
      ), new ProviderConfigProperty(
          KEY_DENY_MESSAGE,
          "deny-message",
          "deny message",
          ProviderConfigProperty.STRING_TYPE,
          DEFAULT_DENY_MESSAGE
      )
  );

  @Override
  public String getDisplayType() {
    return "Cidr filter";
  }

  @Override
  public String getReferenceCategory() {
    return "cert";
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return new AuthenticationExecutionModel.Requirement[] {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.ALTERNATIVE,
        AuthenticationExecutionModel.Requirement.DISABLED
    };
  }

  @Override
  public boolean isUserSetupAllowed() {
    return true;
  }

  @Override
  public String getHelpText() {
    return "filter ip by cidr";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return PROPERTY_LIST;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return this;
  }

  @Override
  public void init(Config.Scope config) {
    //
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    //
  }

  @Override
  public void close() {
    //
  }

  @Override
  public String getId() {
    return IDENTIFY;
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
    var config = context.getAuthenticatorConfig().getConfig();
    if (config == null) {
      responseEnd(context, "config error: config == null");
      return;
    }
    var defaultAllow = BooleanUtils.toBooleanObject(config.getOrDefault(KEY_DEFAULT_ALLOW, "false"));
    boolean isAllow = (defaultAllow == null) ? false : defaultAllow;
    var ruleFullText = config.get(KEY_RULE_LIST);
    var ruleLines = (ruleFullText == null) ? new String[0] : StringUtils.split(ruleFullText, '\n');
    for (int i = 0; i < ruleLines.length; i++) {
      var line = ruleLines[i];
      if (line.length() == 0 || line.charAt(0) == '#') {
        continue;
      }
      boolean allowRule = true;
      if (line.charAt(0) == '-') {
        allowRule = false;
        line = line.substring(1);
      } else if (line.charAt(0) == '+') {
        line = line.substring(1);
      }
      CidrAddress cidrAddress;
      try {
        cidrAddress = new CidrAddress(line);
      } catch (IllegalArgumentException e) {
        responseEnd(context, "config error: " + KEY_RULE_LIST + "[" + i + "] == " + line);
        return;
      }
      if (cidrAddress.getInfo().isInRange(address)) {
        isAllow = allowRule;
        break;
      }
    }
    if(isAllow) {
      context.success();
    }else{
      responseEnd(context, config.getOrDefault(KEY_DENY_MESSAGE, DEFAULT_DENY_MESSAGE));
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    //
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
    //
  }

  private static void responseEnd(AuthenticationFlowContext context, String userErrorMessage) {
    context.getEvent().error(Errors.ACCESS_DENIED);
    Response challenge = context.form()
        .setError(userErrorMessage)
        .createErrorPage(Response.Status.UNAUTHORIZED);
    context.failure(AuthenticationFlowError.ACCESS_DENIED, challenge);
  }
}
