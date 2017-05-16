package com.lyle.des;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sun.security.rsa.RSAPrivateKeyImpl;
import sun.security.rsa.RSAPublicKeyImpl;
import sun.security.util.DerValue;

/**
 * @ClassName: RSAUtil
 * @Description: RSA加密工具类commons-codec.jar
 * @author: Lyle
 * @date: 2017年5月13日 下午5:18:27
 */
public class RSAUtil {

	/** 日志 */
	private static final Logger LOGGER = LoggerFactory.getLogger(RSAUtil.class);

	private static final Charset CHARSET = Charset.forName("UTF-8");

	private static final String RSA = "RSA";

	private static final int ENCODE_MAX_1024 = 117;

	private static final int DECODE_MAX_1024 = 128;

	private static final int ENCODE_MAX_2048 = 245;

	private static final int DECODE_MAX_2048 = 256;

	private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";

	private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";

	/**
	 * @Title: generatorKey
	 * @Description: 生成公私钥
	 * @param keysize 1024/2048
	 * @return: Map<String,String>
	 */
	public static Map<String, String> generatorKey(int keysize) {
		KeyPairGenerator kpg = null;
		Map<String, String> map = new HashMap<>();
		try {
			kpg = KeyPairGenerator.getInstance(RSA);
		} catch (NoSuchAlgorithmException e) {
			//
			return map;
		}
		kpg.initialize(keysize, new SecureRandom());
		KeyPair kp = kpg.generateKeyPair();
		RSAPublicKey public_key = (RSAPublicKey) kp.getPublic();
		RSAPrivateKey private_key = (RSAPrivateKey) kp.getPrivate();
		String publicKey = Base64.encodeBase64String(public_key.getEncoded());
		String privateKey = Base64.encodeBase64String(private_key.getEncoded());
		map.put(KeyEnum.PUBLICKEY.getCode(), publicKey);
		map.put(KeyEnum.PRIVATEKEY.getCode(), privateKey);
		return map;
	}

	/**
	 * @Title: is1024Or2048ByPublicKey
	 * @Description: 判断公钥是1024还是2048
	 * @param publicKey
	 * @return: int
	 */
	public static int is1024Or2048ByPublicKey(String publicKey) {
		try {
			byte[] decodeBase64 = Base64.decodeBase64(publicKey);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodeBase64);
			KeyFactory keyFactory = KeyFactory.getInstance(RSA);
			RSAPublicKey pk = (RSAPublicKey) keyFactory.generatePublic(keySpec);
			return pk.getModulus().bitLength();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			LOGGER.error(e.toString());
			return -1;
		}
	}

	/**
	 * @Title: is1024Or2048ByPrivateKey
	 * @Description: 判断私钥是1024还是2048
	 * @param privateKey
	 * @return: int
	 */
	public static int is1024Or2048ByPrivateKey(String privateKey) {
		try {
			byte[] decodeBase64 = Base64.decodeBase64(privateKey);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodeBase64);
			KeyFactory keyFactory = KeyFactory.getInstance(RSA);
			RSAPrivateKey pk = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
			return pk.getModulus().bitLength();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			LOGGER.error(e.toString());
			return -1;
		}
	}

	/**
	 * @Title: decryptByPrivate
	 * @Description: 私钥解密
	 *               <p>
	 *               RSA加解密: 1024位的证书，加密时最大支持117个字节，解密时为128；
	 *               </p>
	 *               <p>
	 *               2048位的证书，加密时最大支持245个字节，解密时为256。 <br>
	 *               加密时支持的最大字节数：证书位数/8 -11（比如：2048位的证书，支持的最大加密字节数：2048/8 - 11 = 245）
	 *               </p>
	 * @param result 加密后的结果
	 * @param privateKey 私钥
	 * @param mode 加密模型1024/2048
	 * @return: String
	 */
	public static String decryptByPrivate(String result, String privateKey, EncryptionModeEnum mode) {
		try {
			byte[] desEncodeRead = Base64.decodeBase64(privateKey);
			DerValue d = new DerValue(desEncodeRead);
			RSAPrivateKey pk = (RSAPrivateKey) RSAPrivateKeyImpl.parseKey(d);
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.DECRYPT_MODE, pk);
			byte[] src = Base64.decodeBase64(result);
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			if (null == mode || mode.equals(EncryptionModeEnum.RSA1024)) {
				for (int i = 0; i < src.length; i += DECODE_MAX_1024) {
					byte[] toDecodeSegment = ArrayUtils.subarray(src, i, i + DECODE_MAX_1024);
					byte[] destByte = cipher.doFinal(toDecodeSegment);
					out.write(destByte);
				}
			} else if (mode.equals(EncryptionModeEnum.RSA2048)) {
				for (int i = 0; i < src.length; i += DECODE_MAX_2048) {
					byte[] toDecodeSegment = ArrayUtils.subarray(src, i, i + DECODE_MAX_2048);
					byte[] destByte = cipher.doFinal(toDecodeSegment);
					out.write(destByte);
				}
			}
			byte[] decode = out.toByteArray();
			return new String(decode, CHARSET);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | IOException e) {
			LOGGER.error(e.toString());
			return "";
		}
	}

	/**
	 * @Title: encryptByPublic
	 * @Description: 公钥加密
	 * @param src 原数据
	 * @param publicKey 公钥
	 * @param mode 加密模型1024/2048
	 * @return: String
	 */
	public static String encryptByPublic(String src, String publicKey, EncryptionModeEnum mode) {
		try {
			byte[] desEncodeRead = Base64.decodeBase64(publicKey);
			DerValue d = new DerValue(desEncodeRead);
			RSAPublicKey p = (RSAPublicKey) RSAPublicKeyImpl.parse(d);
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, p);
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			byte[] toEncode = src.getBytes();
			if (null == mode || mode.equals(EncryptionModeEnum.RSA1024)) {
				for (int i = 0; i < toEncode.length; i += ENCODE_MAX_1024) {
					byte[] toEncodeSegment = ArrayUtils.subarray(toEncode, i, i + ENCODE_MAX_1024);
					byte[] ecodeSegemnt = cipher.doFinal(toEncodeSegment);
					out.write(ecodeSegemnt);
				}
			} else if (mode.equals(EncryptionModeEnum.RSA2048)) {
				for (int i = 0; i < toEncode.length; i += ENCODE_MAX_2048) {
					byte[] toEncodeSegment = ArrayUtils.subarray(toEncode, i, i + ENCODE_MAX_2048);
					byte[] ecodeSegemnt = cipher.doFinal(toEncodeSegment);
					out.write(ecodeSegemnt);
				}
			}
			byte[] encode = out.toByteArray();
			return Base64.encodeBase64String(encode);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | IOException e) {
			LOGGER.error(e.toString());
			return "";
		}
	}

	private static String sign(byte[] data, String privateKey) {
		try {
			byte[] keyBytes = Base64.decodeBase64(privateKey);
			PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance(RSA);
			PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
			Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
			signature.initSign(privateK);
			signature.update(data);
			return Base64.encodeBase64String(signature.sign());
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | SignatureException e) {
			LOGGER.error(e.toString());
			return "";
		}
	}

	/**
	 * @Title: sign
	 * @Description: 加签
	 * @param content 原数据
	 * @param privateKey 私钥
	 * @return: String
	 */
	public static String sign(String content, String privateKey) {
		return sign(content.getBytes(CHARSET), privateKey);
	}

	private static boolean verify(byte[] data, String publicKey, String sign) {
		try {
			byte[] keyBytes = Base64.decodeBase64(publicKey);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance(RSA);
			PublicKey publicK = keyFactory.generatePublic(keySpec);
			Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
			signature.initVerify(publicK);
			signature.update(data);
			return signature.verify(Base64.decodeBase64(sign));
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | SignatureException e) {
			LOGGER.error(e.toString());
			return false;
		}
	}

	/**
	 * @Title: verify
	 * @Description: 验签
	 * @param data 原数据
	 * @param publicKey 公钥
	 * @param sign 加签结果
	 * @return: boolean
	 */
	public static boolean verify(String data, String publicKey, String sign) {
		return verify(data.getBytes(CHARSET), publicKey, sign);
	}
}
