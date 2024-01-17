package space.titcsl.a.service;

public interface EmailService {
    void sendVerificationEmail(String to, String otp);
}
