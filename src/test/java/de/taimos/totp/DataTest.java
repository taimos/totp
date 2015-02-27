package de.taimos.totp;

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

public class DataTest {
	
	private static final String KEY = "3132333435363738393031323334353637383930";
	
	
	@Test
	public void testData() {
		byte[] byteArray = new BigInteger(DataTest.KEY, 16).toByteArray();
		TOTPData data = new TOTPData("issuer", "superUser", byteArray);
		Assert.assertNotNull(data);
		Assert.assertArrayEquals(byteArray, data.getSecret());
		Assert.assertEquals(DataTest.KEY, data.getSecretAsHex());
		Assert.assertEquals("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", data.getSecretAsBase32());
		Assert.assertEquals("issuer", data.getIssuer());
		Assert.assertEquals("superUser", data.getUser());
		Assert.assertEquals("otpauth://totp/issuer:superUser", data.getSerial());
		Assert.assertEquals("otpauth://totp/issuer:superUser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=issuer", data.getUrl());
	}
	
	@Test
	public void testCreate() {
		byte[] byteArray = new BigInteger(DataTest.KEY, 16).toByteArray();
		TOTPData data = new TOTPData(byteArray);
		Assert.assertNotNull(data);
		Assert.assertArrayEquals(byteArray, data.getSecret());
		Assert.assertEquals(DataTest.KEY, data.getSecretAsHex());
		Assert.assertEquals("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", data.getSecretAsBase32());
		Assert.assertNull(data.getIssuer());
		Assert.assertNull(data.getUser());
		Assert.assertEquals("otpauth://totp/null:null", data.getSerial());
		Assert.assertEquals("otpauth://totp/null:null?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=null", data.getUrl());
	}
	
	@Test
	public void testCreate2() {
		TOTPData data = TOTPData.create("issuer", "superUser");
		Assert.assertNotNull(data);
		Assert.assertEquals("issuer", data.getIssuer());
		Assert.assertEquals("superUser", data.getUser());
		Assert.assertEquals("otpauth://totp/issuer:superUser", data.getSerial());
	}
	
	@Test
	public void testGenerate() {
		byte[] secret = TOTPData.createSecret();
		Assert.assertNotNull(secret);
		Assert.assertEquals(20, secret.length);
		
		TOTPData data = TOTPData.create();
		Assert.assertNotNull(data);
		Assert.assertEquals(20, data.getSecret().length);
	}
	
}
