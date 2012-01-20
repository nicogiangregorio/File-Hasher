package it.nicogiangregorio.filehasher;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import it.nicogiangregorio.hash.FileHasher;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.junit.Before;
import org.junit.Test;

public class TestClass {

	private int bufferSize;
	private String filePath;
	private String hashAlgorithm;
	private String expected;

	@Before
	public void setup() {
		this.bufferSize = 4096;
		this.hashAlgorithm = "MD5";
		this.filePath = "/home/nickg/test.txt";

		// You can use http://www.fileformat.info/tool/hash.htm
		// on the file specified above
		this.expected = "5f9c7b437e9641a832b1c8e780aa68e0";
	}

	@Test
	public void test() {
		byte[] hashed = null;
		String hashedString = null;
		long start = System.currentTimeMillis();

		try {

			hashed = FileHasher.createFileHash(filePath, hashAlgorithm,
				bufferSize);
			hashedString = FileHasher.toHex(hashed);

		} catch (IOException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println(hashedString + ". Time elapsed: "
				+ (System.currentTimeMillis() - start));
		assertNotNull(hashed);
		assertEquals(hashedString, expected);
	}
}
