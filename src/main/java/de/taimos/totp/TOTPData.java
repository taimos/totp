package de.taimos.totp;

import java.util.Random;

import org.apache.commons.codec.binary.Base32;

public final class TOTPData {

	private static final char[] hexArray = "0123456789ABCDEF".toCharArray();
	private static final Random rnd = new Random();

	private final String issuer;
	private final String user;
	private final byte[] secret;
	
	
	/**
	 * @param issuer the token issuer
	 * @param user the token owner
	 * @param secret the secret
	 */
	public TOTPData(String issuer, String user, byte[] secret) {
		this.issuer = issuer;
		this.user = user;
		this.secret = secret;
	}
	
	/**
	 * @param secret the secret
	 */
	public TOTPData(byte[] secret) {
		this(null, null, secret);
	}

	/**
	 * @return the the token issuer
	 */
	public String getIssuer() {
		return this.issuer;
	}

	/**
	 * @return the the token owner
	 */
	public String getUser() {
		return this.user;
	}

	/**
	 * @return the secret
	 */
	public byte[] getSecret() {
		return this.secret;
	}

	/**
	 * return the secret as HEX string
	 *
	 * @return the HEX string
	 */
	public String getSecretAsHex() {
		char[] hexChars = new char[this.secret.length * 2];
		for (int j = 0; j < this.secret.length; j++) {
			int v = this.secret[j] & 0xFF;
			hexChars[j * 2] = TOTPData.hexArray[v >>> 4];
			hexChars[(j * 2) + 1] = TOTPData.hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
	
	/**
	 * return the secret as BASE32 string
	 *
	 * @return the BASE32 string
	 */
	public String getSecretAsBase32() {
		Base32 base = new Base32();
		return base.encodeToString(this.secret);
	}

	/**
	 * return TOTP URL
	 *
	 * @return the OTPAuth URL (otpauth://totp/<i>issuer</i>:<i>user</i>?secret=<i>secret</i>&issuer=<i>issuer</i>)
	 */
	public String getUrl() {
		String secretString = this.getSecretAsBase32();
		return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s", this.issuer, this.user, secretString, this.issuer);
	}

	/**
	 * return OTPAuth Serial
	 *
	 * @return the OTPAuth serial (otpauth://totp/<i>issuer</i>:<i>user</i>)
	 */
	public String getSerial() {
		return String.format("otpauth://totp/%s:%s", this.issuer, this.user);
	}
	
	/**
	 * @return new {@link TOTPData} with generated secret
	 */
	public static TOTPData create() {
		return new TOTPData(TOTPData.createSecret());
	}
	
	/**
	 * @param issuer the token issuer
	 * @param user the token owner
	 * @return new {@link TOTPData} with generated secret for given issuer and user
	 */
	public static TOTPData create(String issuer, String user) {
		return new TOTPData(issuer, user, TOTPData.createSecret());
	}

	/**
	 * generate TOTP secret with length 20
	 *
	 * @return the generated secret
	 */
	public static byte[] createSecret() {
		byte[] secret = new byte[20];
		TOTPData.rnd.nextBytes(secret);
		return secret;
	}
}
