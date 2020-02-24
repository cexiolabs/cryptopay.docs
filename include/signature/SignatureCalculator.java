package band.cryptopay;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;

public class SignatureCalculator {
	private final byte[] _secret;

	public SignatureCalculator(final String secretBase64) {
		this._secret = Base64.decodeBase64(secretBase64);
	}

	public String sing(String timeStampStr, String httpMethod, String urlPath)
			throws InvalidKeyException, NoSuchAlgorithmException {
		return sing(timeStampStr, httpMethod, urlPath, null);
	}

	public String sing(String timeStampStr, String httpMethod, String urlPath, byte[] bodyRaw)
			throws InvalidKeyException, NoSuchAlgorithmException {

		final String prefixStr = timeStampStr + httpMethod + urlPath;
		final byte[] prefixRaw = prefixStr.getBytes(Charset.forName("UTF-8"));

		final String algo = "HmacSHA256";
		final Mac sha256_HMAC = Mac.getInstance(algo);
		sha256_HMAC.init(new SecretKeySpec(this._secret, algo));

		final byte[] what = bodyRaw != null ? ArrayUtils.addAll(prefixRaw, bodyRaw) : prefixRaw;

		final byte[] signature = sha256_HMAC.doFinal(what);

		return Base64.encodeBase64String(signature);
	}
}