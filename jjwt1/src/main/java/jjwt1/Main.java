package jjwt1;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.Key;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.crypto.spec.SecretKeySpec;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.DefaultJwtSignatureValidator;
import io.jsonwebtoken.impl.crypto.MacProvider;

public class Main {

	public static void main(String[] args) {
		decode();
		encode();
		validar();
	}

	private static void validar() {
		String header = get("header");
		String payload = get("payload");
		String signature = get("signature");
		String secretKey = get("secretKey");

		SignatureAlgorithm sa = SignatureAlgorithm.HS256;
		SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), sa.getJcaName());

		String tokenWithoutSignature = header + "." + payload;

		DefaultJwtSignatureValidator validator = new DefaultJwtSignatureValidator(sa, secretKeySpec);

		boolean valid = validator.isValid(tokenWithoutSignature, signature);

		System.out.println("Valid:" + valid);
	}

	private static void encode() {
		Key key = MacProvider.generateKey();

		System.out.println("Key:" + key);

		Map<String, Object> header = new HashMap<String, Object>();
		header.put(get("valor1"), get("valor2"));
		header.put(get("valor3"), get("valor4"));
		header.put(get("valor5"), get("valor6"));

		String payload = get("valor7");

		String jwtString = Jwts.builder().setHeader(header).setPayload(payload).signWith(SignatureAlgorithm.HS256, key)
				.compact();

		System.out.println("JWT:" + jwtString);
	}

	private static void decode() {
		String token = get("valor8"); 

		String[] chunks = token.split("\\.");

		Base64.Decoder decoder = Base64.getDecoder();

		String header = new String(decoder.decode(chunks[0]));
		String payload = new String(decoder.decode(chunks[1]));
		String signature = chunks[2];

		System.out.println("Header:" + header);

		System.out.println("Payload:" + payload);

		System.out.println("Signature:" + signature);
	}

	public static String get(String propriedade) {

		String result = "";
		InputStream inputStream;

		try {
			Properties prop = new Properties();
			String propFileName = "config.properties";

			inputStream = Main.class.getClass().getClassLoader().getResourceAsStream(propFileName);

			if (inputStream != null) {
				prop.load(inputStream);
			} else {
				throw new FileNotFoundException("property file '" + propFileName + "' not found in the classpath");
			}

			return prop.getProperty(propriedade);

		} catch (Exception e) {
			System.out.println("Exception: " + e);
		} finally {
			// inputStream.close();
		}
		return result;
	}

}
