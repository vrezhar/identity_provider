package am.ysu.identity.service.user;

import am.ysu.identity.dao.user.UserDao;
import am.ysu.identity.dto.request.user.UserInitialsDto;
import am.ysu.identity.security.LegacyAwarePasswordEncoder;
import am.ysu.identity.util.Base64Tools;
import am.ysu.identity.util.user.PasswordRecoveryToken;
import am.ysu.identity.dao.user.OldCredentialsDao;
import am.ysu.identity.domain.user.OldCredentials;
import am.ysu.identity.domain.user.User;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * A service for manipulating users, is responsible for password encoding and verification during login, as well during password recovery
 */
@Service
public class UserService {
    private final UserDao userDao;
    private final LegacyAwarePasswordEncoder passwordEncoder;
    private final OldCredentialsDao oldCredentialsDao;

    public UserService(final UserDao userDao, final LegacyAwarePasswordEncoder passwordEncoder, OldCredentialsDao oldCredentialsDao)
    {
        this.userDao = userDao;
        this.passwordEncoder = passwordEncoder;
        this.oldCredentialsDao = oldCredentialsDao;
    }

    public User save(User user) {
        return userDao.save(user);
    }

    @Transactional
    public void delete(User user){
        userDao.delete(user);
    }

    public Optional<User> findById(Long id){
        if(id == null){
            return Optional.empty();
        }
        return userDao.findById(id);
    }

    /**
     * Searches for a user by given username
     * @param username The username
     * @return The user if they are found
     */
    public Optional<User> findByUsername(String username){
        if(username == null){
            return Optional.empty();
        }
        return userDao.findByUsername(username);
    }

    @Transactional
    public void changeInitials(User user, UserInitialsDto initialsDto) {
        final boolean dataChanged = initialsDto.firstName != null || initialsDto.lastName != null || initialsDto.defaultAccountId != null;
        if(initialsDto.firstName != null) {
            user.setFirstName(initialsDto.firstName);
        }
        if(initialsDto.lastName != null) {
            user.setLastName(initialsDto.lastName);
        }
        if(initialsDto.defaultAccountId != null) {
            user.setDefaultAccountId(initialsDto.defaultAccountId);
        }
        if(dataChanged) {
            userDao.save(user);
        }
    }

    public Optional<User> findByUniqueId(UUID uniqueId){
        if(uniqueId == null){
            return Optional.empty();
        }
        return userDao.findByUniqueId(uniqueId);
    }

    /**
     * Finds a user by given password recovery key
     * @param passwordRecoveryKey the key
     * @return a user, if the recovery key was valid and not expired
     */
    public Optional<User> findByPasswordRecoveryKeyIfNotExpired(String passwordRecoveryKey) throws JsonProcessingException
    {
        if(passwordRecoveryKey == null){
            return Optional.empty();
        }
        Optional<User> userOptional = userDao.findByPasswordRecoveryKey(passwordRecoveryKey);
        if(userOptional.isPresent()){
            final User user = userOptional.get();
            final String tokenString = Base64Tools.decodeAsString(user.getPasswordRecoveryKey());
            PasswordRecoveryToken token = new ObjectMapper().readValue(tokenString, PasswordRecoveryToken.class);
            if(token.hasExpired()){
                user.setPasswordRecoveryKey(null);
                userDao.save(user);
                return Optional.empty();
            }
        }
        return userOptional;
    }

    /**
     * Generates a password recovery key for given user
     * @param user The user
     */
    public void generatePasswordRecoveryKeyFor(User user)
    {
        PasswordRecoveryToken token = PasswordRecoveryToken.generate();
        user.setPasswordRecoveryKey(Base64Tools.encodeToString(token.serialize()));
    }

    /**
     * Checks the user credentials
     * @param username The username
     * @param password The password
     * @return The user if the credentials are valid, empty otherwise
     */
    public Optional<User> checkCredentials(String username, String password)
    {
        Optional<User> userOptional = userDao.findByUsername(username);
        if(userOptional.isPresent()) {
            final User user = userOptional.get();
            if(passwordEncoder.matches(password, user.getPassword())) {
                if(passwordEncoder.isOldAlgorithmMatch()) {
                    user.setPassword(passwordEncoder.encode(password));
                    userDao.save(user);
                }
                return userOptional;
            }
        }
        return Optional.empty();
    }

    /**
     * Creates a new user with given name/password assuming they don't already exist
     * @param username The username
     * @param password The password
     * @return The saved user
     */
    public User createUser(String username, String password) {
        final User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setUniqueId(UUID.randomUUID());
        user.setEnabled(false);
        return userDao.save(user);
    }

    /**
     * Changes the user password. Does not perform a check whether it is the same as previous one
     * @param user The user
     * @param newPassword The new password
     * @return The updated user entity
     */
    @Transactional
    public User changePassword(final User user, String newPassword)
    {
        oldCredentialsDao.save(new OldCredentials(user));
        user.setPassword(passwordEncoder.encode(newPassword));
        return userDao.save(user);
    }

    @Transactional
    public void changeUsername(User user, String username)
    {
        oldCredentialsDao.save(new OldCredentials(user));
        user.setUsername(username);
        userDao.save(user);
    }

    @Transactional
    public User changeCredentials(User user, String newUsername, String newPassword)
    {
        OldCredentials credentials = new OldCredentials(user);
        if(newUsername == null){
            if(newPassword == null){
                return user;
            }
            user.setPassword(passwordEncoder.encode(newPassword));
            oldCredentialsDao.save(credentials);
            return userDao.save(user);
        }
        user.setUsername(newUsername);
        if(newPassword != null){
            user.setPassword(passwordEncoder.encode(newPassword));
        }
        oldCredentialsDao.save(credentials);
        return userDao.save(user);
    }

    public boolean isEnabled(String username)
    {
        return userDao.findByUsername(username).map(User::getEnabled).orElse(false);
    }

    public void enableUser(String username)
    {
        userDao.findByUsername(username).ifPresent(user -> {
            user.setEnabled(true);
            userDao.save(user);
        });
    }

    public void disableUser(String username)
    {
        userDao.findByUsername(username).ifPresent(user -> {
            user.setEnabled(false);
            userDao.save(user);
        });
    }
}
