package com.lyle.des;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @ClassName: AESUtil
 * @Description:
 * @author: Lyle
 * @date: 2017年5月15日 下午10:20:14
 */
public class AESUtil {

	private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

	private static final Charset CHARSET = Charset.forName("UTF-8");

	private static final String AES = "AES";

	private static final Logger LOGGER = LoggerFactory.getLogger(AESUtil.class);

	/**
	 * @Title: encrypt
	 * @Description: 加密
	 * @param src 原数据
	 * @param key 密钥-长度128bits，192bits，256bits
	 * @return: String
	 */
	public static String encrypt(String src, String key) {
		if (key.getBytes(CHARSET).length != 16 && key.getBytes(CHARSET).length != 24
				&& key.getBytes(CHARSET).length != 32) {
			LOGGER.error("密钥长度不正确，{}bits", key.getBytes(CHARSET).length * 8);
			return "";
		}
		try {
			byte[] bytes = key.getBytes(CHARSET);
			SecretKeySpec sks = new SecretKeySpec(bytes, AES);
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, sks);
			byte[] encrypted = cipher.doFinal(src.getBytes(CHARSET));
			return Base64.encodeBase64String(encrypted);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			LOGGER.error(e.toString());
			return "";
		}
	}

	/**
	 * @Title: decrypt
	 * @Description: 解密
	 * @param result 加密后的结果
	 * @param key 密钥-长度128bits，192bits，256bits
	 * @return: String
	 */
	public static String decrypt(String result, String key) {
		if (key.getBytes(CHARSET).length != 16 && key.getBytes(CHARSET).length != 24
				&& key.getBytes(CHARSET).length != 32) {
			LOGGER.error("密钥长度不正确，{}bits", key.getBytes(CHARSET).length * 8);
			return "";
		}
		try {
			byte[] bytes = key.getBytes(CHARSET);
			SecretKeySpec sks = new SecretKeySpec(bytes, AES);
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.DECRYPT_MODE, sks);
			byte[] resultByte = Base64.decodeBase64(result);
			byte[] original = cipher.doFinal(resultByte);
			return new String(original, CHARSET);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			LOGGER.error(e.toString());
			return "";
		}
	}
}
