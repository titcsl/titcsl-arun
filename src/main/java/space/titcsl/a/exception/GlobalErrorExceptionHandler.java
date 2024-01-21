package space.titcsl.a.exception;

public class GlobalErrorExceptionHandler extends RuntimeException{
    public GlobalErrorExceptionHandler(String message) {
        super(message);
    }
}
