package space.titcsl.a.dto;

import lombok.Data;

@Data

public class SignUpRequest {

    private String firstName;

    private String lastName;

    private String email;

    private String password;

    private String phone;

    private String displayName;
}
