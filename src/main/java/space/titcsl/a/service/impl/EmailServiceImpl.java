package space.titcsl.a.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import space.titcsl.a.entity.User;
import space.titcsl.a.exception.GlobalErrorExceptionHandler;
import space.titcsl.a.repository.UserRepository;
import space.titcsl.a.service.EmailService;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender javaMailSender;
    private final UserRepository userRepository;
    private final UUID uuid = UUID.randomUUID();

    @Override
    public void sendVerificationEmail(String to, String otp) {
        Optional<User> optionalUser = userRepository.findByEmail(to);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            // Check if the 'to' email address is not null
            if (to != null) {
                SimpleMailMessage message = new SimpleMailMessage();
                message.setTo(to);
                message.setSubject("Email Verification - Arun Ayurved");
                message.setText("Your OTP for email verification is: " + otp + "\nMessage Id: " + uuid);
                user.setEmailMessageId(String.valueOf(uuid));
                userRepository.save(user);
                javaMailSender.send(message);
            } else {
                // Log or handle the case where 'to' is null
                // For now, let's print a message to the console
                throw new GlobalErrorExceptionHandler("Error sending email click on resending email.");
            }
        }
    }

    @Override
    public void EmailAlertsToUser(String to, String BodyMessage) {
        Optional<User> optionalUser = userRepository.findByEmail(to);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            try {
                if (to != null) {
                    SimpleMailMessage message = new SimpleMailMessage();
                    message.setTo(to);
                    message.setSubject("Email Alerts - Arun Ayurved.");
                    message.setText(BodyMessage + "\nMessage Id: " + uuid);
                    user.setEmailMessageId(String.valueOf(uuid));
                    userRepository.save(user);
                    javaMailSender.send(message);
                } else {
                    throw new GlobalErrorExceptionHandler("Error sending email click on resend email.");
                }
            } catch (Exception e) {
                throw new GlobalErrorExceptionHandler("Error sending email click on resend email.");
            }

        } else {
            throw new GlobalErrorExceptionHandler("Error");
        }
    }

    @Override
    public void sendEmail(String to, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body + "\nMessage Id: " + uuid);
        javaMailSender.send(message);
    }
}
