package io.helixiam.common.security;

import io.helixiam.common.exception.KeyHandlingException;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Vendored from group.mfnr.subscriber.starter.security.utils.RSAKeyReader (starter-security
 * module). Not in the Task 1 file list; pulled in transitively because Task 2 folded
 * group.mfnr.authorization.service.key.KeyMaterialService, which uses it to read the master
 * realm's signing key pair from a classpath/filesystem PEM/DER pair.
 *
 * <p>Deviation: the original read file contents via {@code org.apache.commons.io.IOUtils}, and
 * commons-io is not a helix-iam-server dependency (confirmed via {@code mvn dependency:tree} — not
 * pulled transitively by anything in the pom, same check as VENDOR-MAP.md decision #6 for
 * commons-lang3). Reimplemented with a dependency-free {@code InputStream.readAllBytes()} +
 * {@code new String(bytes, charset)}, which is behaviorally identical to
 * {@code IOUtils.toString(InputStream, Charset)} for this use (both fully drain the stream and
 * decode with the platform default charset here).
 *
 * <p>Helper class to read RSA keys.
 * <p>
 * Keys can be created like this:
 *
 * <pre>
 *  {@code
 *  Generate a 2048-bit RSA private key
 *  $ openssl genrsa -out private_key.pem 2048
 *  Convert private Key to PKCS#8 format (so Java can read it)
 *  $ openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt
 *  Output public key portion in DER format (so Java can read it)
 *  $ openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der
 *  }
 * </pre>
 */
public final class RSAKeyReader {

    private RSAKeyReader() {
        throw new IllegalAccessError("Not allowed");
    }

    /**
     * True when {@code filename} is resolvable as either a filesystem file or a classpath resource
     * (never throws). Lets callers decide whether to import a mounted keypair or fall back to
     * self-generation — e.g. the signing realm self-generates its key in a standalone deployment
     * where no {@code /jks} cutover material is mounted.
     */
    public static boolean exists(final String filename) {
        if (filename == null || filename.isBlank()) {
            return false;
        }
        if (new File(filename).exists()) {
            return true;
        }
        try (final InputStream in = RSAKeyReader.class.getResourceAsStream(filename)) {
            return in != null && in.available() > 0;
        } catch (final IOException e) {
            return false;
        }
    }

    public static RSAPublicKey getPublicKey(final String filename) throws KeyHandlingException {
        try {
            final File publicKeyFile = new File(filename);
            if (publicKeyFile.exists()) { // when file not exist throw KeyHandlingException
                return readPublicKey(new FileInputStream(publicKeyFile));
            } else {
                final InputStream file = RSAKeyReader.class.getResourceAsStream(filename);
                if (file != null && file.available() > 0) {
                    return readPublicKey(file);
                } else {
                    throw new KeyHandlingException(String.format("Classpath cert is not available %s", filename));
                }
            }
        } catch (final IOException e) {
            throw new KeyHandlingException(String.format("Could not find cert on location %s", filename));
        }

    }

    public static RSAPrivateKey getPrivateKey(final String filename) throws KeyHandlingException {
        try {
            final File publicKeyFile = new File(filename);
            if (publicKeyFile.exists()) { // when file not exist throw KeyHandlingException
                return readPrivateKey(new FileInputStream(publicKeyFile));
            } else {
                final InputStream file = RSAKeyReader.class.getResourceAsStream(filename);
                if (file != null && file.available() > 0) {
                    return readPrivateKey(file);
                } else {
                    throw new KeyHandlingException(String.format("Classpath cert is not available %s", filename));
                }
            }
        } catch (final IOException e) {
            throw new KeyHandlingException(String.format("Could not find cert on location %s", filename));
        }
    }

    private static RSAPrivateKey readPrivateKey(final InputStream privateKeyFile) throws KeyHandlingException {
        try {
            final String key = readToString(privateKeyFile);

            final String privateKey = key
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PRIVATE KEY-----", "");

            final byte[] encoded = Base64.getDecoder().decode(privateKey);
            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);

            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

        } catch (final IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new KeyHandlingException(e.getMessage());
        }
    }

    private static RSAPublicKey readPublicKey(final InputStream publicKeyFile) throws KeyHandlingException {
        try {
            final String key = readToString(publicKeyFile);

            final String publicKeyPEM = key
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PUBLIC KEY-----", "");

            final byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);

            return (RSAPublicKey) keyFactory.generatePublic(keySpec);

        } catch (final IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new KeyHandlingException(e.getMessage());
        }
    }

    private static String readToString(final InputStream in) throws IOException {
        return new String(in.readAllBytes(), Charset.defaultCharset());
    }

}
