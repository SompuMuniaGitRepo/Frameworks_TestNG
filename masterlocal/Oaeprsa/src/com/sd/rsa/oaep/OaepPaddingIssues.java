package com.sd.rsa.oaep;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class OaepPaddingIssues {

	public static void main(String[] args) {

		// encdecwithOaepPadding();
		encdecwithOaepPaddingAlgo();

	}

	private static void encdecwithOaepPaddingAlgo() {
		try {
			/*
			 * KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			 * 
			 * kpg.initialize(1024); // speedy generation, but not secure anymore KeyPair kp
			 * = kpg.generateKeyPair(); RSAPublicKey pubkey = (RSAPublicKey) kp.getPublic();
			 * RSAPrivateKey privkey = (RSAPrivateKey) kp.getPrivate();
			 */

			KeyStore ks = KeyStore.getInstance("jks");
			ks.load(new FileInputStream("C:\\SD\\Career\\certs\\JohnsPrivateKey.jks"), "123456".toCharArray());
			PrivateKey privkey = (PrivateKey) ks.getKey("KeyForPaul", "123456".toCharArray());

			InputStream inStream = new FileInputStream("C:\\SD\\Career\\certs\\JohnsPublicKey.cer");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			PublicKey pubkey = cf.generateCertificate(inStream).getPublicKey();

			byte[] data = "123456789".getBytes();

			// --- encrypt with SunJCE
			Cipher oaepFromAlgo = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING", "SunJCE");
			oaepFromAlgo.init(Cipher.ENCRYPT_MODE, pubkey);
			byte[] pt = oaepFromAlgo.doFinal(data);
			byte[] encData = Base64.getUrlEncoder().withoutPadding().encode(pt);
			String encStr = new String(encData, StandardCharsets.UTF_8);

			System.out.println("oaepFromAlgo provider============" + oaepFromAlgo.getProvider().getName());
			System.out.println("decData============" + encStr);

			Security.insertProviderAt(new BouncyCastleProvider(), 1);

			// --- encrypt with BC -- bcprov-jdk15on-159.jar
			Cipher oaepFromInit = Cipher.getInstance("RSA/NONE/OAEPWITHSHA-256ANDMGF1PADDING", BouncyCastleProvider.PROVIDER_NAME);
			OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"),
					PSpecified.DEFAULT);
			oaepFromInit.init(Cipher.DECRYPT_MODE, privkey, oaepParams);
			byte[] decData = Base64.getUrlDecoder().decode(encStr.getBytes());
			byte[] decpt = oaepFromInit.doFinal(decData);
			String decDataStr = new String(decpt, StandardCharsets.UTF_8);
			System.out.println("oaepFromInit provider============" + oaepFromInit.getProvider().getName());
			System.out.println("decData============" + decDataStr);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static void encdecwithOaepPadding() {
		try {
			/*
			 * KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			 * 
			 * kpg.initialize(1024); // speedy generation, but not secure anymore KeyPair kp
			 * = kpg.generateKeyPair(); RSAPublicKey pubkey = (RSAPublicKey) kp.getPublic();
			 * RSAPrivateKey privkey = (RSAPrivateKey) kp.getPrivate();
			 */

			KeyStore ks = KeyStore.getInstance("jks");
			ks.load(new FileInputStream("C:\\SD\\Career\\certs\\JohnsPrivateKey.jks"), "123456".toCharArray());
			PrivateKey privkey = (PrivateKey) ks.getKey("KeyForPaul", "123456".toCharArray());

			InputStream inStream = new FileInputStream("C:\\SD\\Career\\certs\\JohnsPublicKey.cer");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			PublicKey pubkey = cf.generateCertificate(inStream).getPublicKey();

			byte[] data = "123456789".getBytes();

			Security.insertProviderAt(new BouncyCastleProvider(), 1);

			// --- encrypt with BC -- bcprov-jdk15on-159.jar
			Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/OAEPPadding", BouncyCastleProvider.PROVIDER_NAME);
			OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"),
					PSpecified.DEFAULT);
			oaepFromInit.init(Cipher.ENCRYPT_MODE, pubkey, oaepParams);
			byte[] pt = oaepFromInit.doFinal(data);
			byte[] encData = Base64.getUrlEncoder().withoutPadding().encode(pt);
			String encDataStr = new String(encData, StandardCharsets.UTF_8);
			System.out.println("oaepFromInit provider============" + oaepFromInit.getProvider().getName());
			System.out.println("encData============" + encDataStr);

			// --- decrypt with SunJCE
			Cipher oaepFromAlgo = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING", "SunJCE");
			oaepFromAlgo.init(Cipher.DECRYPT_MODE, privkey);
			byte[] decData = Base64.getUrlDecoder().decode(encDataStr.getBytes());
			byte[] decct = oaepFromAlgo.doFinal(decData);

			System.out.println("oaepFromAlgo provider============" + oaepFromAlgo.getProvider().getName());
			System.out.println("decData============" + new String(decct, StandardCharsets.UTF_8));

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
