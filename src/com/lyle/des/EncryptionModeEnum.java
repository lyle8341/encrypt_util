package com.lyle.des;

/**
 * @ClassName: KeyEnum
 * @Description:
 * @author: Lyle
 * @date: 2017年5月14日 下午9:10:48
 */
public enum EncryptionModeEnum {
	RSA1024("1024", "1024"), RSA2048("2048", "2048");

	private String code;

	private String desc;

	private EncryptionModeEnum(String code, String desc) {
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
