package am.ysu.identity.controllers.advice;

import am.ysu.identity.dto.error.Error;
import am.ysu.identity.util.errors.ClientNotFoundException;
import am.ysu.identity.util.errors.TokenValidationException;
import am.ysu.identity.util.errors.UserNotFoundException;
import am.ysu.identity.util.errors.common.BadRequestException;
import am.ysu.identity.util.errors.common.ForbiddenActionException;
import am.ysu.identity.util.errors.common.UnauthorizedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import java.util.*;
import java.util.stream.Collectors;

@RestControllerAdvice
public class ControllerAdvice {
    private static final Logger logger = LoggerFactory.getLogger(ControllerAdvice.class);

    private static final String VALIDATION_FAILURE = "validation.failure";

    private final MessageSource messageSource;

    public ControllerAdvice(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @ExceptionHandler(NoSuchElementException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ResponseBody
    public Error handleNotFoundException(NoSuchElementException ne, HttpServletRequest  request) {
        return Error.notFound(ne).requestParams(request);
    }

    @ExceptionHandler(BindException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ResponseBody
    public Error handleMethodArgumentNotValidException(BindException ex, HttpServletRequest request) {
        final List<FieldError> fieldErrors = ex.getBindingResult().getFieldErrors();
        if(fieldErrors.isEmpty()){
            return Error.badRequest(ex.getGlobalError().getDefaultMessage()).requestParams(request);
        }
        return Error.badRequest(VALIDATION_FAILURE, getErrorDescriptionFromBindingResult(fieldErrors)).requestParams(request);
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ResponseBody
    public Error handleMethodArgumentTypeMismatch(MethodArgumentTypeMismatchException me, HttpServletRequest request) {
        return Error.badRequest(VALIDATION_FAILURE,
                Collections.singletonList(
                        new am.ysu.identity.dto.error.FieldError(me.getName(), messageSource.getMessage(me.getErrorCode(), new Object[]{}, Locale.ENGLISH))
                )
        ).requestParams(request);
    }

    @ExceptionHandler(ForbiddenActionException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    @ResponseBody
    public Error handleForbiddenActions(ForbiddenActionException e, HttpServletRequest request){
        return Error.forbidden(e.getMessage()).requestParams(request);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ResponseBody
    public Error handleConstraintViolationException(ConstraintViolationException cve, HttpServletRequest request)
    {
        Set<ConstraintViolation<?>> violations = cve.getConstraintViolations();
        if(violations != null && !violations.isEmpty()){
            return Error.badRequest(
                    VALIDATION_FAILURE,
                    violations.stream().map(error -> new am.ysu.identity.dto.error.FieldError(error.getPropertyPath().toString(), error.getMessage())).collect(Collectors.toList())
            ).requestParams(request);
        }
        return Error.badRequest(cve.getMessage()).requestParams(request);
    }

    @ExceptionHandler(BadRequestException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ResponseBody
    public Error handleBadRequests(BadRequestException be, HttpServletRequest request) {
        return Error.badRequest(be.getMessage()).requestParams(request);
    }

    @ExceptionHandler(UnauthorizedException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ResponseBody
    public Error handleUnauthorizedException(UnauthorizedException ue, HttpServletRequest request) {
        return Error.unauthorized(ue.getMessage()).requestParams(request);
    }

    @ExceptionHandler(TokenValidationException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    @ResponseBody
    public Error handleTokenException(TokenValidationException e, HttpServletRequest request)
    {
        return Error.forbidden("forbidden", e.getValidationError()).requestParams(request);
    }

    @ExceptionHandler(UserNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ResponseBody
    public Error handleUserException(UserNotFoundException e, HttpServletRequest request) {
        return Error.notFound("not.found", e.getMessage()).requestParams(request);
    }

    @ExceptionHandler(ClientNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ResponseBody
    public Error handleClientException(ClientNotFoundException e, HttpServletRequest request) {
        return Error.notFound("not.found", e.getMessage()).requestParams(request);
    }

    @ExceptionHandler(RuntimeException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ResponseBody
    public Error handleGenericExceptions(Exception e, HttpServletRequest request) {
        logger.error("Unexpected runtime exception of type {}, message is {}; stacktrace:", e.getClass().getSimpleName(), e.getMessage());
        e.printStackTrace();
        return Error.internal("unexpected.error", e.getMessage()).requestParams(request);
    }

    private List<am.ysu.identity.dto.error.FieldError> getErrorDescriptionFromBindingResult(List<FieldError> fieldErrors)
    {
        Locale locale = Locale.US;
        return fieldErrors
                .stream()
                .map(error -> {
                    String messageCode = null;
                    final String[] codes = error.getCodes();
                    if(codes != null){
                        for(String code : codes){
                            messageCode = messageSource.getMessage(code, new Object[]{}, null, locale);
                            if(messageCode != null){
                                break;
                            }
                        }
                    }
                    return new am.ysu.identity.dto.error.FieldError(error.getField(), messageCode == null ? error.getDefaultMessage() : messageCode);
                })
                .collect(Collectors.toList());
    }

}
