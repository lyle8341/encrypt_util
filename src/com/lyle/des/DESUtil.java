package com.lyle.des;

import java.nio.charset.Charset;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @ClassName: DESUtil
 * @Description:des加密
 * @author: Lyle
 * @date: 2017年5月15日 下午10:20:04
 */
public class DESUtil {

	private static final Charset CHARSET = Charset.forName("UTF-8");

	private static final String TRANSFORMATION = "DES/CBC/PKCS5Padding";

	private static final String DES = "DES";

	private static final Logger LOGGER = LoggerFactory.getLogger(DESUtil.class);

	/**
	 * @Title: encrypt
	 * @Description: 加密
	 * @param data 原数据
	 * @param key 密钥-长度为64bits
	 * @return
	 * @return: String
	 */
	public static String encrypt(String data, String key) {
		if (key.getBytes(CHARSET).length * 8 != 64) {
			LOGGER.error("密钥长度不正确；当前是{}bits", key.getBytes(CHARSET).length * 8);
			return "";
		}
		try {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			byte[] k = key.getBytes(CHARSET);
			SecretKey secretKey = SecretKeyFactory.getInstance(DES).generateSecret(new DESKeySpec(k));
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(k));
			byte[] doFinal = cipher.doFinal(data.getBytes(CHARSET));
			return Base64.encodeBase64String(doFinal);
		} catch (Exception e) {
			LOGGER.error(e.toString());
			return "";
		}
	}

	/**
	 * @Title: decrypt
	 * @Description: 解密
	 * @param data 加密后的数据
	 * @param key 密钥-长度为64bits
	 * @return
	 * @return: String
	 */
	public static String decrypt(String data, String key) {
		if (key.getBytes(CHARSET).length * 8 != 64) {
			LOGGER.error("密钥长度不正确；当前是{}bits", key.getBytes(CHARSET).length * 8);
			return "";
		}
		try {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			byte[] k = key.getBytes(CHARSET);
			cipher.init(Cipher.DECRYPT_MODE, SecretKeyFactory.getInstance(DES).generateSecret(new DESKeySpec(k)),
					new IvParameterSpec(k));
			return new String(cipher.doFinal(Base64.decodeBase64(data)), CHARSET);
		} catch (Exception e) {
			LOGGER.error(e.toString());
			return "";
		}
	}
}
