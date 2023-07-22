package bot.inker.keycloak.cidr;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.authentication.authenticators.access.DenyAccessAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public final class CidrAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {
  public static final String IDENTIFY = "cidr-authenticator";
  private CidrAuthenticatorConfig config;

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
    return CidrAuthenticatorConfig.propertyList();
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return new CidrAuthenticator(config);
  }

  @Override
  public void init(Config.Scope config) {
    this.config = new CidrAuthenticatorConfig(config);
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {

  }

  @Override
  public void close() {

  }

  @Override
  public String getId() {
    return IDENTIFY;
  }
}
