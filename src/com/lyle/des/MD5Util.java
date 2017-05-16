package com.lyle.des;

import java.nio.charset.Charset;
import java.security.MessageDigest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @ClassName: MD5Util
 * @Description:
 * @author: Lyle
 * @date: 2017年5月16日 下午1:22:20
 */
public class MD5Util {

	private static final Charset CHARSET = Charset.forName("UTF-8");

	private static final Logger LOGGER = LoggerFactory.getLogger(MD5Util.class);

	private static final String MD5 = "MD5";

	private static final char[] HEXDIGITS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E',
			'F' };

	public static String md5(String source) {
		try {
			byte[] btInput = source.getBytes(CHARSET);
			MessageDigest mdInst = MessageDigest.getInstance(MD5);
			mdInst.update(btInput);
			byte[] md = mdInst.digest();
			// 把密文转换成十六进制的字符串形式
			int j = md.length;
			char str[] = new char[j * 2];
			int k = 0;
			for (int i = 0; i < j; i++) {
				byte tmp = md[i];
				str[k++] = HEXDIGITS[tmp >>> 4 & 0xf];
				str[k++] = HEXDIGITS[tmp & 0xf];
			}
			return new String(str);
		} catch (Exception e) {
			LOGGER.error(e.toString());
			return "";
		}
	}
}
