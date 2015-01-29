package de.taimos.totp;

import java.lang.reflect.Method;

import org.junit.Assert;
import org.junit.Test;

public class TOTPTest {
	
	private static final String KEY = "3132333435363738393031323334353637383930";
	
	
	@Test
	public void otpTests() {
		Assert.assertEquals("755224", this.get(0));
		Assert.assertEquals("450130", this.get(1000));
		Assert.assertEquals("746508", this.get(123456));
		Assert.assertEquals("351973", this.get(987654321));
	}
	
	private String get(long step) {
		try {
			Method getOTP = TOTP.class.getDeclaredMethod("getOTP", long.class, String.class);
			getOTP.setAccessible(true);
			return (String) getOTP.invoke(null, step, TOTPTest.KEY);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
