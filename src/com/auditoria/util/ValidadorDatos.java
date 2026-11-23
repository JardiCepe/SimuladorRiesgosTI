package com.auditoria.util;

import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.regex.Pattern;

public final class ValidadorDatos {

    private static final Pattern PATRON_IPV4 = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}"
                    + "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$"
    );

    private static final Pattern PATRON_CVE = Pattern.compile(
            "^CVE-\\d{4}-\\d{4,7}$"
    );

    private ValidadorDatos() {
    }

    public static String validarTextoNoVacio(String valor, String campo) throws AuditoriaException {
        if (valor == null || valor.trim().isEmpty()) {
            throw new AuditoriaException("El campo '" + campo + "' no puede estar vacío.");
        }
        return valor.trim();
    }

    public static String validarIPv4(String ip) throws AuditoriaException {
        String limpia = validarTextoNoVacio(ip, "Dirección IP");
        if (!PATRON_IPV4.matcher(limpia).matches()) {
            throw new AuditoriaException(
                    "Dirección IPv4 inválida: '" + limpia + "'. Ejemplo válido: 192.168.1.10");
        }
        return limpia;
    }

    public static int validarPuerto(int puerto) throws AuditoriaException {
        if (puerto < 1 || puerto > 65535) {
            throw new AuditoriaException(
                    "Número de puerto fuera de rango (" + puerto + "). Debe estar entre 1 y 65535.");
        }
        return puerto;
    }

    public static int validarPuertoOpcional(int puerto) throws AuditoriaException {
        if (puerto < 0 || puerto > 65535) {
            throw new AuditoriaException(
                    "Puerto asociado inválido (" + puerto + "). Use 0 (sin puerto) o entre 1 y 65535.");
        }
        return puerto;
    }

    public static String validarCodigoCVE(String codigoCVE) throws AuditoriaException {
        String normalizado = validarTextoNoVacio(codigoCVE, "Código CVE").toUpperCase();
        if (!PATRON_CVE.matcher(normalizado).matches()) {
            throw new AuditoriaException(
                    "Formato de CVE inválido: '" + codigoCVE + "'. Ejemplo válido: CVE-2020-0796");
        }
        return normalizado;
    }

    public static double validarPositivo(double valor, String campo) throws AuditoriaException {
        if (Double.isNaN(valor) || Double.isInfinite(valor) || valor <= 0.0) {
            throw new AuditoriaException("El campo '" + campo + "' debe ser mayor que cero.");
        }
        return valor;
    }

    public static double validarNoNegativo(double valor, String campo) throws AuditoriaException {
        if (Double.isNaN(valor) || Double.isInfinite(valor) || valor < 0.0) {
            throw new AuditoriaException("El campo '" + campo + "' no puede ser negativo.");
        }
        return valor;
    }

    public static double validarRango(double valor, double min, double max, String campo)
            throws AuditoriaException {
        if (Double.isNaN(valor) || Double.isInfinite(valor) || valor < min || valor > max) {
            throw new AuditoriaException(
                    String.format("El campo '%s' debe estar entre %.2f y %.2f.", campo, min, max));
        }
        return valor;
    }

    public static String validarProtocolo(String protocolo) throws AuditoriaException {
        String norm = validarTextoNoVacio(protocolo, "Protocolo").toUpperCase();
        if (!"TCP".equals(norm) && !"UDP".equals(norm)) {
            throw new AuditoriaException("Protocolo inválido: '" + protocolo + "'. Use TCP o UDP.");
        }
        return norm;
    }

    public static String validarTipoMedio(String tipoMedio) throws AuditoriaException {
        String limpio = validarTextoNoVacio(tipoMedio, "Tipo de medio");
        if ("LAN".equalsIgnoreCase(limpio)) {
            return "LAN";
        }
        if ("WLAN".equalsIgnoreCase(limpio)) {
            return "WLAN";
        }
        if ("TRONCAL".equalsIgnoreCase(limpio)) {
            return "Troncal";
        }
        throw new AuditoriaException(
                "Tipo de medio inválido: '" + tipoMedio + "'. Use LAN, WLAN o Troncal.");
    }

    public static String validarVectorAtaque(String vector) throws AuditoriaException {
        String limpio = validarTextoNoVacio(vector, "Vector de ataque");
        if ("REMOTO".equalsIgnoreCase(limpio)) {
            return "Remoto";
        }
        if ("LOCAL".equalsIgnoreCase(limpio)) {
            return "Local";
        }
        throw new AuditoriaException(
                "Vector de ataque inválido: '" + vector + "'. Use Remoto o Local.");
    }

    public static String validarTipoEquipoRed(String tipoEquipo) throws AuditoriaException {
        String limpio = validarTextoNoVacio(tipoEquipo, "Tipo de equipo");
        if ("ROUTER".equalsIgnoreCase(limpio) || "ENRUTADOR".equalsIgnoreCase(limpio)) {
            return "Router";
        }
        if ("SWITCH".equalsIgnoreCase(limpio) || "CONMUTADOR".equalsIgnoreCase(limpio)) {
            return "Switch";
        }
        throw new AuditoriaException(
                "Tipo de equipo de red inválido: '" + tipoEquipo + "'. Use Router o Switch.");
    }

    public static LocalDate validarFechaISO(String fechaTexto) throws AuditoriaException {
        String limpio = validarTextoNoVacio(fechaTexto, "Fecha de validez");
        try {
            return LocalDate.parse(limpio);
        } catch (DateTimeParseException ex) {
            throw new AuditoriaException(
                    "Fecha inválida: '" + limpio + "'. Use el formato AAAA-MM-DD (ej. 2026-12-31).",
                    ex);
        }
    }
}
