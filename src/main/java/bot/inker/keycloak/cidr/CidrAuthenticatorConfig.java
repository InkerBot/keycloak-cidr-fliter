package bot.inker.keycloak.cidr;

import org.apache.commons.net.util.SubnetUtils;
import org.keycloak.Config;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class CidrAuthenticatorConfig {
  private static final String DEFAULT_ALLOW_KEY = "default-allow";
  private static final String ALLOW_LIST = "allow-list";
  private static final String BLOCK_LIST = "block-list";

  private final boolean defaultAllow;
  private final List<SubnetUtils> allowList;
  private final List<SubnetUtils> blockList;

  public CidrAuthenticatorConfig(Config.Scope config) {
    this.defaultAllow = config.getBoolean(DEFAULT_ALLOW_KEY, false);
    this.allowList = buildList(config.getArray(ALLOW_LIST));
    this.blockList = buildList(config.getArray(BLOCK_LIST));
  }

  public static List<ProviderConfigProperty> propertyList() {
    return Arrays.asList(
        new ProviderConfigProperty(
            DEFAULT_ALLOW_KEY,
            "default-allow",
            "default allow",
            ProviderConfigProperty.BOOLEAN_TYPE,
            true
        ), new ProviderConfigProperty(
            ALLOW_LIST,
            "allow-list",
            "allow list",
            ProviderConfigProperty.MULTIVALUED_STRING_TYPE,
            new String[0]
        ), new ProviderConfigProperty(
            BLOCK_LIST,
            "block-list",
            "block list",
            ProviderConfigProperty.MULTIVALUED_STRING_TYPE,
            new String[0]
        )
    );
  }

  private static List<SubnetUtils> buildList(String[] lines) {
    if (lines == null) {
      return Collections.emptyList();
    }
    var result = new ArrayList<SubnetUtils>();
    for (String line : lines) {
      result.add(new SubnetUtils(line));
    }
    return Collections.unmodifiableList(result);
  }

  public boolean isAllow(String address){
    boolean result = defaultAllow;
    for (SubnetUtils cidr : allowList) {
      if (cidr.getInfo().isInRange(address)) {
        result = true;
      }
    }
    for (SubnetUtils cidr : blockList) {
      if (cidr.getInfo().isInRange(address)) {
        result = false;
      }
    }
    return result;
  }
}
