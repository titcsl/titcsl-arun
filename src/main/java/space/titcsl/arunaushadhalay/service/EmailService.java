package space.titcsl.arunaushadhalay.service;

public interface EmailService {
    void sendVerificationEmail(String to, String otp);
    void EmailAlertsToUser(String to, String BodyMessage);

    void sendEmail(String to, String subject, String body);
}
