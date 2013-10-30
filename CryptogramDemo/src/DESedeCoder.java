import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

public abstract class DESedeCoder {
	/**
	 * 密钥算法 java支持密钥长度为112位和168位 Bouncy Castle支持密钥成都为128位和192位
	 */
	public static final String KEY_ALGORITHM = "DESede";
	/**
	 * 加密或解密算法/工作模式/填充方式 java6支持NoPadding、PKCS5Padding、ISO10126Padding Bouncy
	 * Castle支持PKCS7Padding
	 * 、ISO10126d2Padding、X932Padding、ISO7816d4Padding、ZeroBytePadding
	 */
	public static final String CIPHER_ALGORITHM = "DESede/ECB/PKCS5Padding";

	/**
	 * 根据二进制密钥生成key对象
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static Key toKey(byte[] key) throws Exception {
		// 实例化DESede密钥材料
		DESedeKeySpec dks = new DESedeKeySpec(key);
		// 实例化密钥工厂
		SecretKeyFactory keyFactory = SecretKeyFactory
				.getInstance(KEY_ALGORITHM);
		// 生成密钥
		return keyFactory.generateSecret(dks);
	}

	/**
	 * 解密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decrypt(byte[] data, byte[] key) throws Exception {
		// 还原密钥
		Key k = toKey(key);
		/**
		 * 实例化 使用PKCS7Padding填充方式，按如下代码实现 Cipher
		 * cipher=Cipher.getInstance(CIPHER_ALGORITHM,"BC");
		 */
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		// 初始化，设置为解密模式
		cipher.init(Cipher.DECRYPT_MODE, k);
		// 执行操作
		return cipher.doFinal(data);
	}

	/**
	 * 加密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encrypt(byte[] data, byte[] key) throws Exception {
		// 还原密钥
		Key k = toKey(key);
		// 实例化
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		// 初始化，设置为加密模式
		cipher.init(Cipher.ENCRYPT_MODE, k);
		// 执行操作
		return cipher.doFinal(data);
	}

	public static byte[] initKey() throws Exception {
		// 实例化
		/**
		 * 使用128位或192位长度的密钥，按如下代码实现 KeyGenerator
		 * kg=KeyGenerator.getInstance(KEY_ALGORITHM,"BC");
		 */
		KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
		/**
		 * 初始化 java支持的密钥的长度为112和168位 bouncy castle支持128和192位
		 */
		kg.init(168);
		// 生成密钥
		SecretKey secretKey = kg.generateKey();
		// 获得密钥的二进制编码格式
		return secretKey.getEncoded();
	}
}
