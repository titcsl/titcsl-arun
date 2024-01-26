package space.titcsl.arunaushadhalay.exception;

public class GlobalErrorExceptionHandler extends RuntimeException{
    public GlobalErrorExceptionHandler(String message) {
        super(message);
    }
}
