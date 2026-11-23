package com.auditoria.util;

public class AuditoriaException extends Exception {

    public AuditoriaException(String mensaje) {
        super(mensaje);
    }

    public AuditoriaException(String mensaje, Throwable causa) {
        super(mensaje, causa);
    }
}
