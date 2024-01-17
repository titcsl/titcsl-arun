package space.titcsl.a.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import space.titcsl.a.service.EmailService;

@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender javaMailSender;


    @Override
    public void sendVerificationEmail(String to, String otp) {
        // Check if the 'to' email address is not null
        if (to != null) {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject("Email Verification");
            message.setText("Your OTP for email verification is: " + otp);
            javaMailSender.send(message);
        } else {
            // Log or handle the case where 'to' is null
            // For now, let's print a message to the console
            System.err.println("Warning: Email address 'to' is null in sendVerificationEmail.");
        }
    }

}
