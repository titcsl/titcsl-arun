package space.titcsl.arunaushadhalay.dto;

import lombok.Data;

@Data
public class VerificationRequest {
    private String email;
    private String otp;

}

