import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public abstract class SHACoder {
	/**
	 * SHA-1消息摘要
	 * 
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static byte[] encodeSHA(byte[] data) throws Exception {
		// 初始化MessageDigest
		MessageDigest md = MessageDigest.getInstance("SHA");
		// 执行消息摘要
		return md.digest(data);
	}

	/**
	 * SHA-256消息摘要
	 * 
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static byte[] encodeSHA256(byte[] data) throws Exception {
		// 初始化MessageDigest
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		// 执行消息摘要
		return md.digest(data);
	}

	/**
	 * SHA-384消息摘要
	 * 
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static byte[] encodeSHA384(byte[] data) throws Exception {
		// 初始化MessageDigest
		MessageDigest md = MessageDigest.getInstance("SHA-384");
		// 执行消息摘要
		return md.digest(data);
	}

	/**
	 * SHA-512消息摘要
	 * 
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static byte[] encodeSHA512(byte[] data) throws Exception {
		// 初始化MessageDigest
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		// 执行消息摘要
		return md.digest(data);
	}
}
