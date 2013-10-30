import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public abstract class DESCoder {
	/**
	 * 密钥算法 java 6只支持56位密码
	 * 
	 */
	public static final String KEY_ALGORITHM = "DES";
	/**
	 * 加密或解密使用的算法/工作模式/填充方式
	 */
	public static final String CIPHER_ALGORITHM = "DES/ECB/PKCS5Padding";

	/**
	 * 将二进制的密钥转换为密钥对象
	 * 
	 * @param key
	 *            二进制密钥
	 * @return 密钥对象
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static Key toKey(byte[] key) throws Exception {
		// 实例化des密钥材料
		DESKeySpec dks = new DESKeySpec(key);
		// 实例化密钥工厂
		SecretKeyFactory keyFactory = SecretKeyFactory
				.getInstance(KEY_ALGORITHM);
		// 生成密钥
		SecretKey secretKey = keyFactory.generateSecret(dks);
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
	 * 生成密钥 java6只支持56位密钥 Bouncy Castle只支持64位密钥
	 * 
	 * @param keySize
	 *            密钥的长度
	 * @return 二进制的密钥
	 * @throws Exception
	 */
	public static byte[] initKey() throws Exception {
		// 实例化密钥生成器
		/*
		 * 要使用64位的密钥，将 KeyGenerator kg=KeyGenerator.getInstance(KEY_ALGORITHM);
		 * kg.init(56); 替换为 KeyGenerator
		 * kg=KeyGenerator.getInstance(KEY_ALGORITHM, "BC"); kg.init(64);
		 */
		KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
		kg.init(56);
		// 生成密钥
		SecretKey secretKey = kg.generateKey();
		// 获得密钥的二进制形式
		return secretKey.getEncoded();
	}
}
