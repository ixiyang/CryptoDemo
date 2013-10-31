import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 
 * java6支持MD2和MD5
 * 
 */
public abstract class MDCoder {

	/**
	 * MD2消息摘要
	 * 
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static byte[] encodeMD2(byte[] data) throws Exception {
		// 初始化MessageDigest
		MessageDigest md = MessageDigest.getInstance("MD2");
		// 执行消息摘要
		return md.digest(data);
	}

	/**
	 * MD5消息摘要
	 * 
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static byte[] encodeMD5(byte[] data) throws Exception {
		// 初始化MessageDigest
		MessageDigest md = MessageDigest.getInstance("MD5");
		// 执行消息摘要
		return md.digest(data);
	}
}
