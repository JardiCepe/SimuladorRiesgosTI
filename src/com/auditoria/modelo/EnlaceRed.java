package com.auditoria.modelo;

import com.auditoria.util.AuditoriaException;
import com.auditoria.util.ValidadorDatos;

public class EnlaceRed {

    private String idEnlace;
    private ActivoRed origen;
    private ActivoRed destino;
    private String tipoMedio;
    private boolean activo;

    public EnlaceRed(String idEnlace, ActivoRed origen, ActivoRed destino,
                     String tipoMedio, boolean activo) throws AuditoriaException {
        setIdEnlace(idEnlace);
        setOrigenDestino(origen, destino);
        setTipoMedio(tipoMedio);
        this.activo = activo;
    }

    // Calcula la probabilidad de salto lateral (0.0 si el enlace está inactivo)
    public double calcularProbSalto() {
        if (!activo) {
            return 0.0;
        }

        double probBaseMedio;
        if ("Troncal".equalsIgnoreCase(tipoMedio)) {
            probBaseMedio = 0.85;
        } else if ("LAN".equalsIgnoreCase(tipoMedio)) {
            probBaseMedio = 0.70;
        } else {
            probBaseMedio = 0.55; // WLAN
        }

        double factorCVSS = Math.max(0.25, destino.getPuntajeCVSS() / 10.0);

        double bonusExposicion = 0.0;
        if ("Crítica".equals(destino.getNivelExposicion())) {
            bonusExposicion = 0.15;
        } else if ("Media".equals(destino.getNivelExposicion())) {
            bonusExposicion = 0.08;
        }

        double prob = probBaseMedio * (0.5 + 0.5 * factorCVSS) + bonusExposicion;
        if (prob > 0.98) {
            prob = 0.98;
        }
        return Math.round(prob * 100.0) / 100.0;
    }

    public boolean estaActivo() {
        return activo;
    }

    public String getIdEnlace() {
        return idEnlace;
    }

    public void setIdEnlace(String idEnlace) throws AuditoriaException {
        this.idEnlace = ValidadorDatos.validarTextoNoVacio(idEnlace, "ID de Enlace").toUpperCase();
    }

    public ActivoRed getOrigen() {
        return origen;
    }

    public ActivoRed getDestino() {
        return destino;
    }

    public void setOrigenDestino(ActivoRed origen, ActivoRed destino) throws AuditoriaException {
        if (origen == null || destino == null) {
            throw new AuditoriaException("Tanto el activo origen como el destino son obligatorios.");
        }
        if (origen.getIdActivo().equalsIgnoreCase(destino.getIdActivo())) {
            throw new AuditoriaException("Un enlace no puede conectar un activo consigo mismo.");
        }
        this.origen = origen;
        this.destino = destino;
    }

    public String getTipoMedio() {
        return tipoMedio;
    }

    public void setTipoMedio(String tipoMedio) throws AuditoriaException {
        this.tipoMedio = ValidadorDatos.validarTipoMedio(tipoMedio);
    }

    public void setActivo(boolean activo) {
        this.activo = activo;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s -> %s | Medio: %s | Estado: %s | Prob. Salto: %.0f%%",
                idEnlace, origen.getIdActivo(), destino.getIdActivo(),
                tipoMedio, activo ? "Activo" : "Inactivo", calcularProbSalto() * 100.0);
    }
}
