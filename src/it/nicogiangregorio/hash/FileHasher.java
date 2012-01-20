package it.nicogiangregorio.hash;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Paths;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for hashing file contents
 * 
 * Provide two methods:
 * 
 * createFileHash() that creates an array of bytes hashing data from binary
 * files toHex() that converts the resulting array to common HEX format.
 * 
 * The typical usage is:
 * 
 * byte[] hashedBytes = FileHasher.createFileHash(path, "MD5", 2048); String
 * result = FileHasher.toHex(hashedBytes);
 * 
 * @author Nico Giangregorio
 * 
 */

public class FileHasher {

	private static final byte[] HEX_TABLE = { (byte) '0', (byte) '1',
			(byte) '2', (byte) '3', (byte) '4', (byte) '5', (byte) '6',
			(byte) '7', (byte) '8', (byte) '9', (byte) 'a', (byte) 'b',
			(byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f' };

	// Enforce non-instantiability
	private FileHasher() {
	}

	/**
	 * Applying an hashing function to bynary content of a given file
	 * 
	 * 
	 * @param path : Path where file is located, must be not null
	 * 
	 * @param hashAlgorithm : Algorithm adopted to hash, may be SHA-1, SHA-2,
	 *            MD5 etc, all that supported by java.security.MessageDigest. If
	 *            null it defaults applies MD5
	 * 
	 * @param bufferSize : size of reading buffer. 2048 or 4096 are suggested
	 *            ones.
	 * @return : Array of bytes containing hashed data.
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] createFileHash(String path, String hashAlgorithm,
			int bufferSize) throws IOException, NoSuchAlgorithmException {

		if (path == null)
			throw new IllegalArgumentException();
		if (bufferSize < 1)
			throw new IllegalArgumentException();

		if (hashAlgorithm == null)
			hashAlgorithm = "MD5";

		File fileToHash = Paths.get(path).toFile();

		int fileLength = (int) fileToHash.length();

		if (fileLength == 0) {
			bufferSize = 1; // in case file is empty
		} else if (fileLength < bufferSize)
			bufferSize = fileLength;

		FileChannel fChan = new FileInputStream(fileToHash).getChannel();
		ByteBuffer buf = ByteBuffer.allocate(bufferSize);
		MessageDigest digester = MessageDigest.getInstance(hashAlgorithm);

		// A masked while loop:
		// it would be enough: while ((fChan.read(buf) > 0),
		// but that computes a bad digest!!!!
		// If fileLength / bufferSize has a remainder greater than 0,
		// the last buffer will be filled with:
		// [bufferSize - remainder] bytes of 0s. eg
		// [bytoFromFile, byteFromFile, lastByteFromFile, 0, 0]
		// and digest will computes the 0s too!!
		// the code below fix this in the last cycle of loop
		for (int ii = fileLength / bufferSize; (fChan.read(buf)) > 0; ii--) {

			buf.rewind();
			digester.update(buf.array());
			buf.compact();
			buf.flip();

			if (ii == 1 && fileLength % bufferSize > 0) {
				buf = ByteBuffer.allocate(fileLength % bufferSize);
			}
		}

		fChan.close();

		return digester.digest();
	}

	/**
	 * Only for comparison purpose, old way to open file
	 * 
	 * @param path : Path to tile
	 * @param hashAlgorithm : algorithm for hash
	 * @return : hashed result
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	@Deprecated
	public static byte[] legacyFileHash(String path, String hashAlgorithm) throws IOException, NoSuchAlgorithmException {

		File file = new File(path);
		MessageDigest md = MessageDigest.getInstance(hashAlgorithm);

		BufferedInputStream bist = new BufferedInputStream(new FileInputStream(file));
		DigestInputStream dist = new DigestInputStream(bist, md);

		while ((dist.read()) != -1)
			;

		return dist.getMessageDigest().digest();
	}

	/**
	 * Convert from byte arrays to HEX format in ASCII
	 * 
	 * @param bytes : input byte array (supposed to be an Hashed data)
	 * 
	 * @return : String of ASCII, hex converted byte array
	 * 
	 * @throws UnsupportedEncodingException
	 */
	public static String toHex(byte[] bytes)
			throws UnsupportedEncodingException {

		if (bytes == null)
			throw new IllegalArgumentException();

		byte[] hex = new byte[2 * bytes.length];
		int index = 0;

		for (byte b : bytes) {
			int v = b & 0xFF;
			hex[index++] = HEX_TABLE[v >>> 4];
			hex[index++] = HEX_TABLE[v & 0xF];
		}
		return new String(hex, "ASCII");
	}
}
