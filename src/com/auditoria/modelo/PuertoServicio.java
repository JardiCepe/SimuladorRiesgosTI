package com.auditoria.modelo;

import com.auditoria.util.AuditoriaException;
import com.auditoria.util.ValidadorDatos;

import java.util.Set;

public class PuertoServicio {

    private static final Set<Integer> PUERTOS_INSEGUROS = Set.of(21, 23, 69, 135, 139, 445, 512, 513, 514, 5900);
    private static final Set<Integer> PUERTOS_EXPOSICION_MEDIA = Set.of(22, 25, 80, 110, 143, 1433, 3306, 3389, 5432, 8080);

    private int numeroPuerto;
    private String protocolo;
    private String servicio;
    private boolean esInseguro;

    public PuertoServicio(int numeroPuerto, String protocolo, String servicio) throws AuditoriaException {
        setNumeroPuerto(numeroPuerto);
        setProtocolo(protocolo);
        setServicio(servicio);
        verificarRiesgoPuerto();
    }

    public boolean verificarRiesgoPuerto() {
        String servLower = servicio.toLowerCase();
        boolean nombreInseguro = servLower.contains("telnet")
                || servLower.contains("ftp") && !servLower.contains("sftp")
                || servLower.contains("smb")
                || servLower.contains("netbios")
                || servLower.contains("rlogin")
                || servLower.contains("vnc");
        this.esInseguro = PUERTOS_INSEGUROS.contains(numeroPuerto) || nombreInseguro;
        return this.esInseguro;
    }

    public String getNivelAlerta() {
        if (verificarRiesgoPuerto()) {
            return "CRÍTICA";
        }
        if (PUERTOS_EXPOSICION_MEDIA.contains(numeroPuerto)) {
            return "MEDIA";
        }
        return "BAJA";
    }

    public int getNumeroPuerto() {
        return numeroPuerto;
    }

    public void setNumeroPuerto(int numeroPuerto) throws AuditoriaException {
        this.numeroPuerto = ValidadorDatos.validarPuerto(numeroPuerto);
        if (this.servicio != null) {
            verificarRiesgoPuerto();
        }
    }

    public String getProtocolo() {
        return protocolo;
    }

    public void setProtocolo(String protocolo) throws AuditoriaException {
        this.protocolo = ValidadorDatos.validarProtocolo(protocolo);
    }

    public String getServicio() {
        return servicio;
    }

    public void setServicio(String servicio) throws AuditoriaException {
        this.servicio = ValidadorDatos.validarTextoNoVacio(servicio, "Servicio");
        verificarRiesgoPuerto();
    }

    public boolean isEsInseguro() {
        return esInseguro;
    }

    @Override
    public String toString() {
        return numeroPuerto + "/" + protocolo + " (" + servicio + ") [" + getNivelAlerta() + "]";
    }
}
