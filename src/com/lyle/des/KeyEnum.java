package com.lyle.des;

/**
 * @ClassName: KeyEnum
 * @Description:
 * @author: Lyle
 * @date: 2017年5月14日 下午9:10:48
 */
public enum KeyEnum {
	PUBLICKEY("publicKey", "公钥"), PRIVATEKEY("privateKey", "私钥");

	private String code;

	private String desc;

	private KeyEnum(String code, String desc) {
		this.code = code;
		this.desc = desc;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getDesc() {
		return desc;
	}

	public void setDesc(String desc) {
		this.desc = desc;
	}
}
