package am.ysu.identity.service.key;

import am.ysu.identity.domain.client.Client;
import am.ysu.identity.domain.security.keys.ServerKeyMetadata;
import am.ysu.identity.domain.security.keys.ec.EcKey;
import am.ysu.identity.domain.security.keys.ec.EdEcKey;
import am.ysu.identity.domain.security.keys.rsa.RsaKey;
import am.ysu.identity.domain.user.User;
import am.ysu.identity.util.jwt.KeyProvider;
import am.ysu.security.security.EncryptionParameters;
import am.ysu.security.security.util.aes.HashingAndEncryptionHelper;
import am.ysu.security.security.util.key.KeyUtils;
import am.ysu.security.security.util.key.NistEcCurve;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.NonUniqueResultException;
import javax.persistence.TypedQuery;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class PersistentKeyManager {
    private static final IvParameterSpec IV = new IvParameterSpec(new byte[]{
            0x02b, 0x01b, 0x02b, 0x01b,
            0x01b, 0x01b, 0x02b, 0x07b,
            0x01b, 0x03b, 0x02b, 0x01b,
            0x01b, 0x01b, 0x02b, 0x05b
    });
    private static final byte[] SALT = new byte[]{
            0x05b, 0x04b, 0x00b, 0x07b,
            0x07b, 0x06b, 0x06b, 0x07b,
            0x02b, 0x02b, 0x0b, 0x04b,
            0x00b, 0x00b, 0x07b, 0x05b
    };
    private static final Logger logger = LoggerFactory.getLogger(PersistentKeyManager.class);

    private final EntityManager entityManager;
    private final SecureRandom random;

    @Value("${security.preferEllipticKeys}")
    private boolean preferEcKeys;

    @Value("${security.useSeparateUserKeys}")
    private boolean useSeparateUserKeys;

    @Value("${security.encryptPrivateKeys}")
    private boolean encryptPrivateKeys;

    public PersistentKeyManager(EntityManager entityManager) {
        this.entityManager = entityManager;
        try {
            this.random = SecureRandom.getInstanceStrong();
        } catch(Exception e) {
            throw new RuntimeException("Unexpected secure random init failure", e);
        }
    }

    @Transactional
    public Optional<ServerKeyMetadata> findKey(String keyId) {
        final var query = entityManager.createNamedQuery(ServerKeyMetadata.FIND_BY_ID_QUERY, ServerKeyMetadata.class);
        query.setParameter("keyId", keyId);
        return extractQueryResult(query);
    }

//    @Override
    public PublicKey getPublicKey(String keyId) {
        return findPublicKey(keyId).orElseThrow(() -> new NoSuchElementException("not.found"));
    }

//    @Override
    public PrivateKey getPrivateKey(String keyId) {
        return getKeyPair(keyId).orElseThrow(() -> new NoSuchElementException("not.found")).getPrivate();
    }

//    @Override
    public KeyPair getAsKeyPair(String keyId) {
        return getKeyPair(keyId).orElseThrow(() -> new NoSuchElementException("not.found"));
    }

    @Transactional
    public Optional<KeyPair> getKeyPair(String keyId) {
        final var optionalMetadata = findKey(keyId);
        if(optionalMetadata.isEmpty()) {
            return Optional.empty();
        }
        final var metadata = optionalMetadata.get();
        if(metadata.getEncrypted()) {
            logger.warn("Key {} is encrypted, no password provided", keyId);
            return Optional.empty();
        }
        return getKeyPair(metadata);
    }

//    @Override
    public KeyPair getKeyPair(User user) {
        if(useSeparateUserKeys) {
            final var query = entityManager.createNamedQuery(ServerKeyMetadata.FIND_USER_KEY_QUERY, ServerKeyMetadata.class);
            query.setParameter("user", user);
            final var keys = extractList(query);
            if(keys.isEmpty()) {
                return generateKeyPair(user);
            }
            return getKeyPair(keys.get(random.nextInt(keys.size()))).orElseThrow(() -> new NoSuchElementException("not.found"));
        }
        final var query = entityManager.createNamedQuery(ServerKeyMetadata.FIND_ALL_COMMON_KEYS_QUERY, ServerKeyMetadata.class);
        final var keys = extractList(query);
        if(keys.isEmpty()) {
            return generateKeyPair(ServerKeyMetadata.KeyAlgorithm.EC);
        }
        return getKeyPair(keys.get(random.nextInt(keys.size()))).orElseThrow(() -> new NoSuchElementException("not.found"));
    }

    @Transactional
    public Optional<? extends PublicKey> findPublicKey(String keyId) {
        final var metadata = findKey(keyId);
        if(metadata.isEmpty()) {
            return Optional.empty();
        }
        return findPublicKey(metadata.get());
    }

    @Transactional
    public Optional<KeyPair> getKeyPair(ServerKeyMetadata metadata) {
        final String keyId = metadata.getKeyId();
        final var query = metadata.getKeyFetchingQuery(entityManager);
        try {
            return getKeyPair(extractQueryResult(query));
        } catch (Exception e) {
            logger.warn("Unexpected exception of type {} encountered when trying to fetch key {} of type {}: {}",
                    e.getClass().getSimpleName(), keyId, metadata.getAlgorithm(), e.getMessage());
            return Optional.empty();
        }
    }

    @Transactional
    public Optional<? extends PublicKey> findPublicKey(ServerKeyMetadata metadata) {
        final String keyId = metadata.getKeyId();
        final var query = metadata.getKeyFetchingQuery(entityManager);
        try {
            return getPublicKey(extractQueryResult(query));
        } catch (Exception e) {
            logger.warn("Unexpected exception of type {} encountered when trying to fetch public key {} of type {}: {}",
                    e.getClass().getSimpleName(), keyId, metadata.getAlgorithm(), e.getMessage());
            return Optional.empty();
        }
    }

    @Transactional
    public List<? extends PublicKey> getAllUserPublicKeys() {
        final var query = entityManager.createNamedQuery(ServerKeyMetadata.FIND_ALL_USER_KEYS_QUERY, ServerKeyMetadata.class);
        return doGetPublicKeys(query);
    }

    @Transactional
    public List<? extends PublicKey> getAllClientPublicKeys() {
        final var query = entityManager.createNamedQuery(ServerKeyMetadata.FIND_ALL_USER_KEYS_QUERY, ServerKeyMetadata.class);
        return doGetPublicKeys(query);
    }

    @Transactional
    public List<? extends PublicKey> getAllCommonPublicKeys() {
        final var query = entityManager.createNamedQuery(ServerKeyMetadata.FIND_ALL_COMMON_KEYS_QUERY, ServerKeyMetadata.class);
        return doGetPublicKeys(query);
    }

    public KeyPair generateKeyPair(Client client) {
        if(preferEcKeys) {
            return generateKeyPair(client, ServerKeyMetadata.KeyAlgorithm.EC);
        }
        int check = random.nextInt()%2;
        if(check == 1) {
            return generateKeyPair(client, ServerKeyMetadata.KeyAlgorithm.EC);
        }
        return generateKeyPair(client, ServerKeyMetadata.KeyAlgorithm.RSA);
    }

    public KeyPair generateKeyPair(Client client, String password) {
        if(!encryptPrivateKeys || password == null) {
            return generateKeyPair(client);
        }
        if(preferEcKeys) {
            return generateKeyPair(client, ServerKeyMetadata.KeyAlgorithm.EC, password);
        }
        int check = random.nextInt()%2;
        if(check == 1) {
            return generateKeyPair(client, ServerKeyMetadata.KeyAlgorithm.EC, password);
        }
        return generateKeyPair(client, ServerKeyMetadata.KeyAlgorithm.RSA, password);
    }

    public KeyPair generateKeyPair(User user) {
        if(!useSeparateUserKeys && getAllCommonPublicKeys().size() < 3) {
            return generateKeyPair(ServerKeyMetadata.KeyAlgorithm.EC);
        }
        if(preferEcKeys) {
            return generateKeyPair(user, ServerKeyMetadata.KeyAlgorithm.EC);
        }
        int check = random.nextInt()%2;
        if(check == 1) {
            return generateKeyPair(user, ServerKeyMetadata.KeyAlgorithm.EC);
        }
        return generateKeyPair(user, ServerKeyMetadata.KeyAlgorithm.RSA);
    }

//    @Override
    public List<String> availableKeys() {
        final var userKeys = availableUserKeys();
        final var serverKeys = availableServerKeys();
        final var clientKeys = getAllClientPublicKeys()
                .stream()
                .map(KeyUtils::calculateFingerPrintHex)
                .collect(Collectors.toList());
        final var result = new ArrayList<String>(userKeys.size() + serverKeys.size() + clientKeys.size());
        result.addAll(userKeys);
        result.addAll(clientKeys);
        result.addAll(serverKeys);
        return result;
    }

//    @Override
    public List<String> availableServerKeys() {
        return getAllCommonPublicKeys()
                .stream()
                .map(KeyUtils::calculateFingerPrintHex)
                .collect(Collectors.toList());
    }

//    @Override
    public List<String> availableUserKeys() {
        return getAllUserPublicKeys()
                .stream()
                .map(KeyUtils::calculateFingerPrintHex)
                .collect(Collectors.toList());
    }

    public KeyPair generateKeyPair(User user, String password) {
        if(!useSeparateUserKeys && getAllCommonPublicKeys().size() < 3) {
            if(!encryptPrivateKeys || password == null) {
                return generateKeyPair(ServerKeyMetadata.KeyAlgorithm.EC);
            }
            return generateKeyPair(ServerKeyMetadata.KeyAlgorithm.EC);
        }
        if(!encryptPrivateKeys || password == null) {
            return generateKeyPair(user);
        }
        if(preferEcKeys) {
            return generateKeyPair(user, ServerKeyMetadata.KeyAlgorithm.EC, password);
        }
        int check = random.nextInt()%2;
        if(check == 1) {
            return generateKeyPair(user, ServerKeyMetadata.KeyAlgorithm.EC, password);
        }
        return generateKeyPair(user, ServerKeyMetadata.KeyAlgorithm.RSA, password);
    }

    @Transactional
    public KeyPair generateKeyPair(ServerKeyMetadata.KeyAlgorithm algorithm) {
        final var keys = algorithm.generateKeyPair();
        final String keyId = KeyUtils.calculateFingerPrintHex(keys.getPublic());
        final ServerKeyMetadata metadata = createMetadata(algorithm, keyId);
        entityManager.persist(metadata);
        doSave(metadata, keys);
        return keys;
    }

    @Transactional
    public KeyPair generateKeyPair(ServerKeyMetadata.KeyAlgorithm algorithm, String password) {
        final var keys = algorithm.generateKeyPair();
        final String keyId = KeyUtils.calculateFingerPrintHex(keys.getPublic());
        final ServerKeyMetadata metadata = createMetadata(algorithm, keyId);
        metadata.setEncrypted(true);
        entityManager.persist(metadata);
        doSave(metadata, keys, password);
        return keys;
    }

    @Transactional
    public KeyPair generateKeyPair(Client client, ServerKeyMetadata.KeyAlgorithm algorithm) {
        final var keys = algorithm.generateKeyPair();
        final String keyId = KeyUtils.calculateFingerPrintHex(keys.getPublic());
        final ServerKeyMetadata metadata = createMetadata(algorithm, keyId);
        metadata.setClient(client);
        entityManager.persist(metadata);
        doSave(metadata, keys);
        return keys;
    }

    @Transactional
    public KeyPair generateKeyPair(Client client, ServerKeyMetadata.KeyAlgorithm algorithm, String password) {
        final var keys = algorithm.generateKeyPair();
        final String keyId = KeyUtils.calculateFingerPrintHex(keys.getPublic());
        final ServerKeyMetadata metadata = createMetadata(algorithm, keyId);
        metadata.setClient(client);
        metadata.setEncrypted(true);
        entityManager.persist(metadata);
        doSave(metadata, keys, password);
        return keys;
    }

    @Transactional
    public KeyPair generateKeyPair(User user, ServerKeyMetadata.KeyAlgorithm algorithm) {
        final var keys = algorithm.generateKeyPair();
        final String keyId = KeyUtils.calculateFingerPrintHex(keys.getPublic());
        final ServerKeyMetadata metadata = createMetadata(algorithm, keyId);
        metadata.setUser(user);
        entityManager.persist(metadata);
        doSave(metadata, keys);
        return keys;
    }

    @Transactional
    public KeyPair generateKeyPair(User user, ServerKeyMetadata.KeyAlgorithm algorithm, String password) {
        final var keys = algorithm.generateKeyPair();
        final String keyId = KeyUtils.calculateFingerPrintHex(keys.getPublic());
        final ServerKeyMetadata metadata = createMetadata(algorithm, keyId);
        metadata.setUser(user);
        metadata.setEncrypted(true);
        entityManager.persist(metadata);
        doSave(metadata, keys, password);
        return keys;
    }

    protected void doSave(ServerKeyMetadata metadata, KeyPair keyPair) {
        doSave(metadata, keyPair, null);
    }

    protected void doSave(ServerKeyMetadata metadata, KeyPair keyPair, String password) {
        final var publicKey = keyPair.getPublic();
        final var privateKey = keyPair.getPrivate();
        if(publicKey instanceof RSAPublicKey rsaPublicKey && privateKey instanceof RSAPrivateKey rsaPrivateKey) {
            doSave(metadata, rsaPublicKey, rsaPrivateKey, password);
            return;
        }
        if(publicKey instanceof ECPublicKey ecPublicKey && privateKey instanceof ECPrivateKey ecPrivateKey) {
            doSave(metadata, ecPublicKey, ecPrivateKey, password);
            return;
        }
        if(publicKey instanceof EdECPublicKey edECPublicKey && privateKey instanceof EdECPrivateKey edECPrivateKey) {
            doSave(metadata, edECPublicKey, edECPrivateKey, password);
            return;
        }
        throw new IllegalArgumentException("Unknown public/private key types [" + publicKey.getClass().getSimpleName() +
                "][" +  privateKey.getClass().getSimpleName() + "]");
    }

    @Transactional
    protected void doSave(ServerKeyMetadata metadata, RSAPublicKey publicKey, RSAPrivateKey privateKey, String password) {
        if(password == null) {
            final var key = new RsaKey(privateKey, publicKey);
            key.setServerKeyMetadata(metadata);
            entityManager.persist(key);
            return;
        }
        final var d = encrypt(password, privateKey.getPrivateExponent().toByteArray());
        final var n = publicKey.getModulus().toByteArray();
        final var e = publicKey.getPublicExponent().toByteArray();
        final var key = new RsaKey();
        key.setServerKeyMetadata(metadata);
        key.setD(d);
        key.setE(e);
        key.setN(n);
        entityManager.persist(key);
    }

    @Transactional
    protected void doSave(ServerKeyMetadata metadata, ECPublicKey publicKey, ECPrivateKey privateKey, String password) {
        if(password == null) {
            final var key = new EcKey(privateKey, publicKey);
            key.setServerKeyMetadata(metadata);
            entityManager.persist(key);
            return;
        }
        final var s = encrypt(password, privateKey.getS().toByteArray());
        final ECPoint w = publicKey.getW();
        final var wx = w.getAffineX().toByteArray();
        final var wy = w.getAffineY().toByteArray();
        final var key = new EcKey();
        key.setServerKeyMetadata(metadata);
        key.setS(s);
        key.setWx(wx);
        key.setWy(wy);
        entityManager.persist(key);
    }

    @Transactional
    protected void doSave(ServerKeyMetadata metadata, EdECPublicKey publicKey, EdECPrivateKey privateKey, String password) {
        if(password == null) {
            final var key = new EdEcKey(privateKey, publicKey);
            key.setServerKeyMetadata(metadata);
            entityManager.persist(key);
            return;
        }
        final var h = encrypt(password, privateKey.getBytes().orElseThrow(() -> new RuntimeException("Private key not available")));
        final var point = publicKey.getPoint();
        final var xOdd = point.isXOdd();
        final var y = point.getY().toByteArray();
        final var key = new EdEcKey();
        key.setServerKeyMetadata(metadata);
        key.setH(h);
        key.setXOdd(xOdd);
        key.setY(y);
        entityManager.persist(key);
    }

    public static KeyPair getKeyPair(RsaKey rsaKey) throws InvalidKeySpecException {
        final var e = new BigInteger(rsaKey.getE());
        final var n = new BigInteger(rsaKey.getN());
        final var d = new BigInteger(rsaKey.getD());
        return getRsaKeyPair(e, n, d);
    }

    public static RSAPublicKey getPublicKey(RsaKey rsaKey) throws InvalidKeySpecException {
        final var keyFactory = KeyUtils.getRsaKeyFactory();
        final var e = new BigInteger(rsaKey.getE());
        final var n = new BigInteger(rsaKey.getN());
        final var publicKeySpec = new RSAPublicKeySpec(n, e);
        return (RSAPublicKey)keyFactory.generatePublic(publicKeySpec);
    }

    public static KeyPair getKeyPair(RsaKey rsaKey, String password) throws InvalidKeySpecException {
        if(!rsaKey.getServerKeyMetadata().getEncrypted()) {
            return getKeyPair(rsaKey);
        }
        final var e = new BigInteger(rsaKey.getE());
        final var n = new BigInteger(rsaKey.getN());
        final var d = new BigInteger(decrypt(password, rsaKey.getD()));
        return getRsaKeyPair(e, n, d);
    }

    public static KeyPair getKeyPair(EcKey ecKey) throws InvalidKeySpecException {
        final var s = new BigInteger(ecKey.getS());
        final var wx = new BigInteger(ecKey.getWx());
        final var wy = new BigInteger(ecKey.getWy());
        final var curve = NistEcCurve.forName(ecKey.getCurveId());
        return getEcKeyPair(wx, wy, s, curve);
    }

    public static KeyPair getKeyPair(EcKey ecKey, String password) throws InvalidKeySpecException {
        if(!ecKey.getServerKeyMetadata().getEncrypted()) {
            return getKeyPair(ecKey);
        }
        final var wx = new BigInteger(ecKey.getWx());
        final var wy = new BigInteger(ecKey.getWy());
        final var s = new BigInteger(decrypt(password, ecKey.getS()));
        final var curve = NistEcCurve.forName(ecKey.getCurveId());
        return getEcKeyPair(wx, wy, s, curve);
    }

    public static ECPublicKey getPublicKey(EcKey ecKey) throws InvalidKeySpecException {
        final var keyFactory = KeyUtils.getEccKeyFactory();
        final var wX = new BigInteger(ecKey.getWx());
        final var wy = new BigInteger(ecKey.getWy());
        final var curve = NistEcCurve.forName(ecKey.getCurveId());
        final var publicKeySpec = new ECPublicKeySpec(new ECPoint(wX, wy), curve.getParameterSpec());
        return (ECPublicKey)keyFactory.generatePublic(publicKeySpec);
    }

    public static KeyPair getKeyPair(EdEcKey edEcKey) throws InvalidKeySpecException {
        final var keyFactory = KeyUtils.getEdECKeyFactory();
        final var y = new BigInteger(edEcKey.getY());
        final var publicKeySpec = new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(edEcKey.getXOdd(), y));
        final var privateKeySpec = new EdECPrivateKeySpec(NamedParameterSpec.ED25519, edEcKey.getH());
        return new KeyPair(keyFactory.generatePublic(publicKeySpec), keyFactory.generatePrivate(privateKeySpec));
    }

    public static KeyPair getKeyPair(EdEcKey edEcKey, String password) throws InvalidKeySpecException {
        if(!edEcKey.getServerKeyMetadata().getEncrypted()) {
            return getKeyPair(edEcKey);
        }
        final var keyFactory = KeyUtils.getEdECKeyFactory();
        final var y = new BigInteger(edEcKey.getY());
        final var publicKeySpec = new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(edEcKey.getXOdd(), y));
        final var privateKeySpec = new EdECPrivateKeySpec(NamedParameterSpec.ED25519, decrypt(password, edEcKey.getH()));
        return new KeyPair(keyFactory.generatePublic(publicKeySpec), keyFactory.generatePrivate(privateKeySpec));
    }

    public static EdECPublicKey getPublicKey(EdEcKey edEcKey) throws InvalidKeySpecException {
        final var keyFactory = KeyUtils.getEdECKeyFactory();
        final var y = new BigInteger(edEcKey.getY());
        final var publicKeySpec = new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(edEcKey.getXOdd(), y));
        return (EdECPublicKey)keyFactory.generatePublic(publicKeySpec);
    }

    private ServerKeyMetadata createMetadata(ServerKeyMetadata.KeyAlgorithm algorithm, String keyId) {
        final var metadata = new ServerKeyMetadata();
        metadata.setAlgorithm(algorithm);
        metadata.setKeyId(keyId);
        metadata.setExpirationDate(LocalDateTime.now().plusDays(30));//This can be configured
        return metadata;
    }

    private List<? extends PublicKey> doGetPublicKeys(TypedQuery<ServerKeyMetadata> query) {
        return extractList(query)
                .stream()
                .map(this::findPublicKey)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toList());
    }

    private static KeyPair getRsaKeyPair(BigInteger e, BigInteger n, BigInteger d) throws InvalidKeySpecException {
        final var keyFactory = KeyUtils.getRsaKeyFactory();
        final var publicKeySpec = new RSAPublicKeySpec(n, e);
        final var privateKeySpec = new RSAPrivateKeySpec(n, d);
        return new KeyPair(keyFactory.generatePublic(publicKeySpec), keyFactory.generatePrivate(privateKeySpec));
    }

    private static KeyPair getEcKeyPair(BigInteger wx, BigInteger wy, BigInteger s, NistEcCurve curve) throws InvalidKeySpecException {
        final var keyFactory = KeyUtils.getEccKeyFactory();
        final var publicKeySpec = new ECPublicKeySpec(new ECPoint(wx, wy), curve.getParameterSpec());
        final var privateKeySpec = new ECPrivateKeySpec(s, curve.getParameterSpec());
        return new KeyPair(keyFactory.generatePublic(publicKeySpec), keyFactory.generatePrivate(privateKeySpec));
    }

    private static Optional<KeyPair> getKeyPair(Object key) throws InvalidKeySpecException {
        if(key instanceof RsaKey rsaKey) {
            return Optional.of(getKeyPair(rsaKey));
        }
        if(key instanceof EcKey ecKey) {
            return Optional.of(getKeyPair(ecKey));
        }
        if(key instanceof EdEcKey edEcKey) {
            return Optional.of(getKeyPair(edEcKey));
        }
        logger.warn("Unknown key type " + key.getClass().getSimpleName());
        return Optional.empty();
    }

    private static Optional<? extends PublicKey> getPublicKey(Object publicKey) throws InvalidKeySpecException {
        if(publicKey instanceof RsaKey rsaKey) {
            return Optional.of(getPublicKey(rsaKey));
        }
        if(publicKey instanceof EcKey ecKey) {
            return Optional.of(getPublicKey(ecKey));
        }
        if(publicKey instanceof EdEcKey edEcKey) {
            return Optional.of(getPublicKey(edEcKey));
        }
        logger.warn("Unknown key type " + publicKey.getClass().getSimpleName());
        return Optional.empty();
    }

    private static <T> Optional<T> extractQueryResult(TypedQuery<T> query) {
        try {
            return Optional.ofNullable(query.getSingleResult());
        } catch (NonUniqueResultException e) {
            logger.warn("SELECT query did not return a single result as it was supposed to");
            return Optional.empty();
        } catch (NoResultException ignored) {
            return Optional.empty();
        } catch (Exception e) {
            logger.warn("Unexpected exception of type {} encountered when executing SELECT query: {}",
                    e.getClass().getSimpleName(), e.getMessage());
            return Optional.empty();
        }
    }

    private static <T> List<T> extractList(TypedQuery<T> query) {
        try {
            final var result = query.getResultList();
            if(result == null) {
                return new ArrayList<>();
            }
            return result;
        } catch (Exception e) {
            logger.warn("Unexpected exception of type {} encountered when executing SELECT query: {}",
                    e.getClass().getSimpleName(), e.getMessage());
            return new ArrayList<>();
        }
    }

    private static byte[] encrypt(String password, byte[] data) {
        try {
            final var context = HashingAndEncryptionHelper.encryptUsingPassword(new String(data, StandardCharsets.ISO_8859_1), password, SALT, IV);
            return context.encryptedData.getBytes(StandardCharsets.ISO_8859_1);
        } catch (
                InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException |
                NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | InvalidKeySpecException e
        ) {
            logger.info("Unable to encrypt data due to an exception of type {}: {}", e.getClass().getSimpleName(), e.getMessage());
            return data;
        }
    }

    private static byte[] decrypt(String password, byte[] data) {
        try {
            final var context = HashingAndEncryptionHelper.decrypt(new String(data, StandardCharsets.ISO_8859_1),
                    createEncryptionParameters(password));
            return context.getBytes(StandardCharsets.ISO_8859_1);
        } catch (
                InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException |
                NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | InvalidKeySpecException e
        ) {
            logger.info("Unable to decrypt data due to an exception of type {}: {}", e.getClass().getSimpleName(), e.getMessage());
            return data;
        }
    }

    private static EncryptionParameters createEncryptionParameters(String password) throws InvalidKeySpecException {
        return new EncryptionParameters(IV, password, SALT);
    }
}
