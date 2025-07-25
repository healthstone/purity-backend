package org.acme.service;

import jakarta.enterprise.context.ApplicationScoped;
import org.acme.utils.SRP6;

@ApplicationScoped
public class AuthService {
    private final SRP6 srp = new SRP6();

    public void regAccount(String accName, String password) {
        // Регистрация:
        SRP6.GeneratedVerifier gv = srp.generateSaltAndVerifierTrinity(accName, password);
        // Сохраняем gv.salt и gv.verifier в базу
    }

    public boolean checkCredentials(String accName, String password, byte[] saltFromDb, byte[] verifierFromDb) {
        // Проверка пароля при логине:
        boolean valid = srp.verifyPassword(accName, password, saltFromDb, verifierFromDb);
        if (valid) {
            System.out.println("Пароль верный");
        } else {
            System.out.println("Неверный пароль");
        }
        return valid;
    }
}
