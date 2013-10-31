import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public abstract class MACCoder {
	/**
	 * 初始化HmacMD5密钥
	 * 
	 * @return
	 * @throws Exception
	 */
	public static byte[] initHmacMD5Key() throws Exception {
		// 初始化KeyGenerator
		KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
		// 产生密钥
		SecretKey key = keyGen.generateKey();
		// 获得密钥
		return key.getEncoded();
	}

	/**
	 * HmacMD5消息摘要
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encodeHmacMD5(byte[] data, byte[] key)
			throws Exception {
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacMD5");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化
		mac.init(secretKey);
		// 执行消息摘要
		return mac.doFinal(data);
	}

	/**
	 * 初始化HmacSHA1密钥
	 * 
	 * @return
	 * @throws Exception
	 */
	public static byte[] initHmacSHAKey() throws Exception {
		// 初始化KeyGenerator
		KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
		// 产生密钥
		SecretKey key = keyGen.generateKey();
		// 获得密钥
		return key.getEncoded();
	}

	/**
	 * HmacSHA1消息摘要
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encodeHmacSHA(byte[] data, byte[] key)
			throws Exception {
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacSHA1");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化
		mac.init(secretKey);
		// 执行消息摘要
		return mac.doFinal(data);
	}

	/**
	 * 初始化HmacSHA256密钥
	 * 
	 * @return
	 * @throws Exception
	 */
	public static byte[] initHmacSHA256Key() throws Exception {
		// 初始化KeyGenerator
		KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
		// 产生密钥
		SecretKey key = keyGen.generateKey();
		// 获得密钥
		return key.getEncoded();
	}

	/**
	 * HmacSHA256消息摘要
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encodeHmacSHA256(byte[] data, byte[] key)
			throws Exception {
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacSHA256");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化
		mac.init(secretKey);
		// 执行消息摘要
		return mac.doFinal(data);
	}

	/**
	 * 初始化HmacSHA384密钥
	 * 
	 * @return
	 * @throws Exception
	 */
	public static byte[] initHmacSHA384Key() throws Exception {
		// 初始化KeyGenerator
		KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA384");
		// 产生密钥
		SecretKey key = keyGen.generateKey();
		// 获得密钥
		return key.getEncoded();
	}

	/**
	 * HmacSHA384消息摘要
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encodeHmacSHA384(byte[] data, byte[] key)
			throws Exception {
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacSHA384");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化
		mac.init(secretKey);
		// 执行消息摘要
		return mac.doFinal(data);
	}

	/**
	 * 初始化HmacSHA512密钥
	 * 
	 * @return
	 * @throws Exception
	 */
	public static byte[] initHmacSHA512Key() throws Exception {
		// 初始化KeyGenerator
		KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA512");
		// 产生密钥
		SecretKey key = keyGen.generateKey();
		// 获得密钥
		return key.getEncoded();
	}

	/**
	 * HmacSHA512消息摘要
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encodeHmacSHA512(byte[] data, byte[] key)
			throws Exception {
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacSHA512");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化
		mac.init(secretKey);
		// 执行消息摘要
		return mac.doFinal(data);
	}
}
