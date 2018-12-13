import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

public class Main implements Serializable {

	private KeyPairGenerator keyPairGenerator; // Генератор ключевых пар
	private KeyPair keyPair; // Пара ключей
	private PrivateKey privateKey; // Приватный ключ
	private PublicKey publicKey; // Открытый ключ
	private Signature signature; // Цифровая подпись
	private byte[] realSign; // массив байтов подписи для записи в файл
	private final static String messageFile = "message.docx"; // файл с сообщением
	private final static String signFile = "sign.txt"; // файл с подписью
	private final static String publickeyFile = "publickey.txt"; // файл с открытым ключом
	private final static String privatekeyFile = "privatekey.txt"; // файл с закрытым ключом

	public static void main(String[] args)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException,
			IOException, NullPointerException, ClassNotFoundException, ClassCastException {

		Main main = new Main("RSA", 1024, "SHA1withRSA", null);// генерируем ключи
		main.signingMessage(new FileOutputStream(signFile)); // генерируем подпись и записываем ее в файл

		System.out.println("Сообщение: \n" + Arrays.toString(readFromFile(messageFile)));// вывод сообщения

		System.out.println("Открытый ключ: \n" + main.readPublicKey(new FileInputStream(publickeyFile)));// вывод открытого ключа
		main.savePublicKey(new FileOutputStream(publickeyFile)); // сохраняем открытый ключ

		main.savePrivateKey(new FileOutputStream(privatekeyFile)); // сохраняем закрытый ключ

		System.out.println("Подпись: \n" + Arrays.toString(main.realSign));// вывод подписи
		System.out.println();

		if (main.verifyMessage() == true) // проверка подписи
			System.out.println("Проверка подписи прошла успешно");
		else
			System.out.println("Проверка подписи не прошла");

	}

	/**
	 * Конструктор. Генерирует пары ключей на основании введенных данных, и
	 * сохраняет их в поля класса
	 * 
	 * @param keyAlg
	 *            - название алгоритма для которого ген. пара ключей
	 * @param keyLenght
	 *            - длина ключей
	 * @param signAlg
	 *            - алгоритм цифровой подписи
	 * @param provName
	 *            - название крипто провайдера (Можно указать null)
	 * @throws NullPointerException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public Main(String keyAlg, int keyLenght, String signAlg, String provName)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		// проверяем входные данные
		if ((keyAlg == null) || (signAlg == null)) {
			throw new NullPointerException();
		} else {
			// проверяем длину ключа
			if (keyLenght <= 0) {
				System.out.println("error on key lenght - " + keyLenght);
			}
			// генерация ключей и подписи
			keyPairGenerator = KeyPairGenerator.getInstance(keyAlg);
			keyPairGenerator.initialize(keyLenght, new SecureRandom());
			keyPair = keyPairGenerator.generateKeyPair();
			publicKey = keyPair.getPublic();
			privateKey = keyPair.getPrivate();
			if (provName == null) {
				signature = Signature.getInstance(signAlg);
			} else {
				signature = Signature.getInstance(signAlg, provName);
			}
		}
	}

	/**
	 * ф-ия создает цифровую подпись из указаного открытого текста
	 * 
	 * @param msgPath
	 *            - поток ввода с открытым текстом
	 * @param sgnPath
	 *            - поток вывода с созданой цифровой подписью
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public void signingMessage(FileOutputStream sgnPath) throws IOException, NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeyException, SignatureException {
		// проверка на существование файла, в который будет записана подпись
		if (sgnPath == null) {
			throw new NullPointerException();
		}
		// проверка на существование закрытого ключа
		if (privateKey == null) {
			throw new IllegalArgumentException();
		}
		// читаем файл с сообщением, создаем для него подпись, сохраняем подпись в файл
		signature.initSign(privateKey);
		byte[] byteMsg = readFromFile(messageFile);
		signature.update(byteMsg);
		realSign = signature.sign();
		sgnPath.write(realSign);

	}

	/**
	 * ф-ия проверяет действительность цифровой подписи
	 * 
	 * @param msg
	 *            - поток ввода с открытым текстом
	 * @param sgn
	 *            - поток ввода с цифровой подписью
	 * @return - возвращает результат проверки цифровой подписи
	 * @throws InvalidKeyException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws SignatureException
	 */
	public boolean verifyMessage() throws InvalidKeyException, FileNotFoundException, IOException, SignatureException {

		// читаем файл с сообщением
		byte[] byteMsg = readFromFile(messageFile);

		// читаем файл подписи
		byte[] byteSgn = readFromFile(signFile);

		// проверка подписи
		signature.initVerify(publicKey);
		signature.update(byteMsg);
		boolean result = signature.verify(byteSgn);

		return result;
	}

	/**
	 * ф-ия сохраняет приватный ключ
	 * 
	 * @param file
	 *            - поток вывода, где будет сохранен закрытый ключ
	 * @throws IOException
	 */
	public void savePrivateKey(FileOutputStream file) throws IOException {
		// проверяем входные параметры
		if (file == null && privateKey == null) {
			return;
		} else {
			// записываем закрытый ключ в файл
			ObjectOutputStream objStrm = new ObjectOutputStream(file);
			objStrm.writeObject(privateKey);
			System.out.println("Закрытый ключ сохранен в " + privatekeyFile);
			objStrm.close();
		}
	}

	/**
	 * ф-ия сохраняет открытый ключ
	 * 
	 * @param file
	 *            - поток вывода, где будет сохранен открытый ключ
	 * @throws IOException
	 */
	public void savePublicKey(FileOutputStream file) throws IOException {
		// проверяем входные параметры
		if (file == null && publicKey == null) {
			return;
		} else {
			// записываем открытый ключ в файл
			ObjectOutputStream objStrm = new ObjectOutputStream(file);
			objStrm.writeObject(publicKey);
			System.out.println("Открытый ключ сохранен в " + publickeyFile);
			objStrm.close();
		}
	}

	/**
	 * ф-ия считывает файл из указанного потока
	 * 
	 * @param fRead
	 *            - потока ввода
	 * @return - возвращает приватный ключ
	 * @throws NullPointerException
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws ClassCastException
	 */
	public PrivateKey readPrivateKey(FileInputStream fRead)
			throws NullPointerException, IOException, ClassNotFoundException, ClassCastException {
		//проверка входных данных
		if (fRead == null) {
			throw new NullPointerException();
		} else {
			//читаем файл с закрытым ключом
			ObjectInputStream obRead = new ObjectInputStream(fRead);
			Object ob = obRead.readObject();
			//если объект в файле является закрытым ключом, то возвращаем его
			//в противном случае генерируем исключение
			if (ob instanceof PrivateKey) {
				PrivateKey privKey = (PrivateKey) ob;
				return privKey;
			} else {
				throw new ClassCastException();
			}
		}
	}

	/**
	 * ф-ия считывает открытый ключ из указанного потока ввода
	 * 
	 * @param fRead
	 *            - поток ввода
	 * @return - возвращает открытый ключ
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws ClassCastException
	 */
	public PublicKey readPublicKey(FileInputStream fRead)
			throws IOException, ClassNotFoundException, ClassCastException {
		//проверка входных данных
		if (fRead == null) {
			throw new NullPointerException();
		} else {
			//читаем файл с открытым ключом
			ObjectInputStream obRead = new ObjectInputStream(fRead);
			Object ob = obRead.readObject();
			//если объект в файле является открытым ключом, то возвращаем его
			//в противном случае генерируем исключение
			if (ob instanceof PublicKey) {
				PublicKey privKey = (PublicKey) ob;
				return privKey;
			} else {
				throw new ClassCastException();
			}
		}
	}

	/**
	 * ф-ия чтения из файла
	 * 
	 * @param fileName
	 *            - имя файла
	 * @return - возвращает массив байтов
	 */
	public static byte[] readFromFile(String fileName) {
		byte[] data;
		try {
			//чтение файла
			FileInputStream fis = new FileInputStream(fileName);
			data = new byte[fis.available()];
			fis.read(data);
			fis.close();
			//если возникло исключение, то сообщаем об ошибке 
			//в противном случае возвращаем массив байтов из файла
		} catch (Exception e) {
			System.err.println("Возникло исключение: " + e.toString());
			data = new byte[0];
		}
		return (data);
	}

	
	public void setPrivateKey(PrivateKey prk) {
		privateKey = prk;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPublicKey(PublicKey pbk) {
		publicKey = pbk;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public byte[] getSign() {
		return realSign;
	}
}
