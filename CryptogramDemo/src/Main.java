import java.util.Map;

import com.sun.org.apache.bcel.internal.generic.NEW;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

public class Main {

	/**
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		// testDES();
		// testDESede();
		// testRSA();
		// testMD();
		// testSHA();
		//testMac();
		testAES();
	}

	public static void testDES() throws Exception {
		String inputStr = "DES";
		byte[] inputData = inputStr.getBytes();
		System.out.println("原文：" + inputStr);
		// 初始化密钥
		byte[] key = DESCoder.initKey();
		System.out.println("密钥:" + new String(key));
		// 加密
		inputData = DESCoder.encrypt(inputData, key);
		System.out.println("加密后:" + new String(inputData));
		// 解密
		byte[] outputData = DESCoder.decrypt(inputData, key);
		System.out.println("解密后:" + new String(outputData));
	}

	public static void testDESede() throws Exception {
		String inputStr = "DESede";
		byte[] inputData = inputStr.getBytes();
		System.out.println("原文：" + inputStr);
		// 初始化密钥
		byte[] key = DESedeCoder.initKey();
		System.out.println("密钥:" + new String(key));
		// 加密
		inputData = DESedeCoder.encrypt(inputData, key);
		System.out.println("加密后:" + new String(inputData));
		// 解密
		byte[] outputData = DESedeCoder.decrypt(inputData, key);
		System.out.println("解密后:" + new String(outputData));
	}

	public static void testRSA() throws Exception {
		// 初始化密钥
		Map<String, Object> keyMap = RSACoder.initKey();
		// 公钥
		byte[] publicKey = RSACoder.getPublicKey(keyMap);
		// 私钥
		byte[] privateKey = RSACoder.getPrivateKey(keyMap);
		System.out.println("公钥:\n" + new String(publicKey));
		System.out.println("私钥:\n" + new String(privateKey));

		String inputStr = "RSA加密算法";
		byte[] inputData = inputStr.getBytes();
		System.out.println("私钥加密---公钥解密");
		// 私钥加密
		inputData = RSACoder.encryptByPrivateKey(inputData, privateKey);
		System.out.println("私钥加密后:\n" + new String(inputData));
		// 公钥解密
		inputData = RSACoder.decryptByPublicKey(inputData, publicKey);
		System.out.println("公钥解密后:\n" + new String(inputData));

		//
		System.out.println("公钥加密--私钥解密");
		// 公钥加密
		inputData = RSACoder.encryptByPublicKey(inputData, publicKey);
		System.out.println("公钥加密后:\n" + new String(inputData));
		// 私钥解密
		inputData = RSACoder.decryptByPrivateKey(inputData, privateKey);
		System.out.println("私钥解密后:\n" + new String(inputData));

	}

	public static void testMD() throws Exception {
		String str = "MD2消息摘要";
		System.out.println("MD2消息摘要");
		System.out.println(new String(MDCoder.encodeMD2(str.getBytes())));
		str = "MD5消息摘要";
		System.out.println("MD5消息摘要");
		System.out.println(Base64.encode((MDCoder.encodeMD5(str.getBytes()))));

	}

	public static void testSHA() throws Exception {
		String str = "SHA消息摘要";
		// SHA
		System.out.println(Base64.encode(SHACoder.encodeSHA(str.getBytes())));
		// SHA-256
		System.out
				.println(Base64.encode(SHACoder.encodeSHA256(str.getBytes())));
		// SHA-384
		System.out
				.println(Base64.encode(SHACoder.encodeSHA384(str.getBytes())));
		// SHA-512
		System.out
				.println(Base64.encode(SHACoder.encodeSHA512(str.getBytes())));
	}

	public static void testMac() throws Exception {
		String str = "Mac消息摘要";
		System.out.println("HmacMD5");
		// 密钥
		byte[] key = MACCoder.initHmacMD5Key();
		byte[] encode = MACCoder.encodeHmacMD5(str.getBytes(), key);
		System.out.println(Base64.encode(encode));

		System.out.println("HmacSHA");
		// 密钥
		key = MACCoder.initHmacSHAKey();
		encode = MACCoder.encodeHmacSHA(str.getBytes(), key);
		System.out.println(Base64.encode(encode));

		System.out.println("HmacSHA256");
		// 密钥
		key = MACCoder.initHmacSHA256Key();
		encode = MACCoder.encodeHmacSHA256(str.getBytes(), key);
		System.out.println(Base64.encode(encode));

		System.out.println("HmacSHA384");
		// 密钥
		key = MACCoder.initHmacSHA384Key();
		encode = MACCoder.encodeHmacSHA384(str.getBytes(), key);
		System.out.println(Base64.encode(encode));

		System.out.println("HmacSHA512");
		// 密钥
		key = MACCoder.initHmacSHA512Key();
		encode = MACCoder.encodeHmacSHA512(str.getBytes(), key);
		System.out.println(Base64.encode(encode));
	}

	public static void testAES() throws Exception {
		String str = "AES加密";
		byte[] data=str.getBytes();
		System.out.println("密钥");
		byte[] key=AESCoder.initKey();
		System.out.println(Base64.encode(key));
		System.out.println("加密后");
		data=AESCoder.encrypt(data, key);
		System.out.println(Base64.encode(data));
		System.out.println("解密后");
		data=AESCoder.decrypt(data, key);
		System.out.println(new String(data));
	}
}
