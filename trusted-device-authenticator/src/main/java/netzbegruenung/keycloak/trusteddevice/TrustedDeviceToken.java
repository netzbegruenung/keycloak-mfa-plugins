package netzbegruenung.keycloak.trusteddevice;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.common.util.Time;
import org.keycloak.representations.JsonWebToken;

public class TrustedDeviceToken extends JsonWebToken {

    @JsonProperty("device_id")
    private String deviceId;

    public TrustedDeviceToken() {
    }

    public TrustedDeviceToken(String id, String deviceId, Long exp) {
        this.id = id;
        this.deviceId = deviceId;
        iat((long) Time.currentTime());
        exp(exp);
    }

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }
}
