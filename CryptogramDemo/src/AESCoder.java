import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public abstract class AESCoder {

	/**
	 * 算法名称
	 */
	public static final String KEY_ALGORITHM = "AES";
	/**
	 * 加密或者解密的算法/工作模式/填充方式 java6支持PKCS5Padding bouncy castle支持PKCS7Padding
	 */
	public static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";

	/**
	 * 返回Key对象
	 * 
	 * @param key
	 * @return
	 */
	public static Key toKey(byte[] key) {
		SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
		return secretKey;
	}

	/**
	 * 解密操作
	 * 
	 * @param data
	 *            加密数据
	 * @param key
	 *            密钥
	 * @return 解密后的数据
	 * @throws Exception
	 */
	public static byte[] decrypt(byte[] data, byte[] key) throws Exception {
		// 还原密钥
		Key k = toKey(key);
		// 实例化
		/**
		 * 使用PKCS7Padding Cipher cipher =
		 * Cipher.getInstance(CIPHER_ALGORITHM，"BC");
		 */
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		// 初始化，设置为解密模式
		cipher.init(Cipher.DECRYPT_MODE, k);
		// 执行操作
		return cipher.doFinal(data);
	}

	/**
	 * 加密数据
	 * 
	 * @param data
	 *            要加密的数据
	 * @param key
	 *            密钥
	 * @return 加密之后的数据
	 * @throws Exception
	 */
	public static byte[] encrypt(byte[] data, byte[] key) throws Exception {
		// 还原密钥
		Key k = toKey(key);
		// 实例化加密对象
		Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
		// 初始化，设置为加密模式
		cipher.init(Cipher.ENCRYPT_MODE, k);
		// 执行加密
		return cipher.doFinal(data);
	}

	/**
	 * 生成密钥
	 * 
	 * @return
	 * @throws Exception
	 */
	public static byte[] initKey() throws Exception {
		// 实例化密钥生成器
		/*
		 * AEC要求密钥长度为128,192和256位
		 */
		KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
		kg.init(128);
		// 生成密钥
		SecretKey secretKey = kg.generateKey();
		// 获得密钥的二进制形式
		return secretKey.getEncoded();
	}
}
