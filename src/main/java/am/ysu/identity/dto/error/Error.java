package am.ysu.identity.dto.error;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.springframework.http.HttpStatus;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class Error {
    private String path;
    private String timestamp;
    private String message;
    private String details;
    private List<FieldError> errors;
    private int status;

    private Error() { }

    @JsonInclude(value = JsonInclude.Include.NON_NULL)
    public List<FieldError> getErrors() {
        return errors;
    }

    public void setErrors(List<FieldError> errors) {
        this.errors = errors;
    }

    @JsonInclude(value = JsonInclude.Include.NON_NULL)
    public String getMessage() {
        return message;
    }

    @JsonInclude(value = JsonInclude.Include.NON_NULL)
    public void setMessage(String message) {
        this.message = message;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public Error message(String message)
    {
        this.message = message;
        return this;
    }

    public Error timestamp()
    {
        this.timestamp = DateTimeFormatter.ISO_DATE_TIME.format(LocalDateTime.now());
        return this;
    }

    public Error requestParams(HttpServletRequest request)
    {
        ServletWebRequest webRequest = new ServletWebRequest(request);
        final String path = (String) webRequest.getAttribute(RequestDispatcher.ERROR_REQUEST_URI, RequestAttributes.SCOPE_REQUEST);
        this.path = path != null ? path : request.getServletPath();
        return this.timestamp();
    }

    public static Error internal(String message, String errorDescription)
    {
        Error error = new Error();
        error.message = message;
        error.status = HttpStatus.INTERNAL_SERVER_ERROR.value();
        error.details = errorDescription;
        return error;
    }

    public static Error internal(String message){
        return internal(message, "Internal server error");
    }

    public static Error notFound(Throwable t) {
        Error error = new Error();
        error.message = t.getMessage();
        error.status = HttpStatus.NOT_FOUND.value();
        error.details = "Not found";
        return error;
    }

    public static Error notFound(String message, String description){
        Error error = new Error();
        error.message = message;
        error.status = HttpStatus.NOT_FOUND.value();
        error.details = description;
        return error;
    }

    public static Error notFound(String description){
        return notFound("Not found", description);
    }

    public static Error forbidden(String message, String details)
    {
        Error error = new Error();
        error.message = message;
        error.status = HttpStatus.FORBIDDEN.value();
        error.details = details;
        return error;
    }
    public static Error forbidden(String message) {
        return forbidden(message, "Access denied");
    }


    public static Error unauthorized(String message)
    {
        Error error = new Error();
        error.message = message;
        error.status = HttpStatus.UNAUTHORIZED.value();
        error.details = "Authorization required";
        return error;
    }

    public static Error badRequest(String message, String description)
    {
        Error error = new Error();
        error.message = message;
        error.status = HttpStatus.BAD_REQUEST.value();
        error.details = description;
        return error;
    }

    public static Error badRequest(String message, List<FieldError> validationErrors)
    {
        Error error = new Error();
        error.message = message;
        error.status = HttpStatus.BAD_REQUEST.value();
        error.errors = validationErrors;
        error.details = "Validation error";
        return error;
    }

    public static Error badRequest(String message){
        return badRequest(message, "Bad request");
    }

    public static Error unprocessableEntity(String message, String errorDescription)
    {
        Error error = new Error();
        error.message = message;
        error.status = HttpStatus.UNPROCESSABLE_ENTITY.value();
        error.details = errorDescription;
        return error;
    }

    public static Error ofStatus(HttpStatus status)
    {
        if(status.is4xxClientError() || status.is5xxServerError()){
            Error error = new Error();
            error.status = status.value();
            return error;
        }
        throw new IllegalArgumentException("HTTP status supplied is not an error status");
    }
}
