package com.auditoria.modelo;

import com.auditoria.util.AuditoriaException;
import com.auditoria.util.ValidadorDatos;

public class AccionMitigacion {

    private String idAccion;
    private ActivoRed activo;
    private Vulnerabilidad vulnerabilidad;
    private String tipoAccion;
    private double costoEstimado;
    private double horasHombre;
    private double reduccionRiesgo;
    private boolean aplicada;

    public AccionMitigacion(String idAccion, ActivoRed activo, Vulnerabilidad vulnerabilidad,
                            String tipoAccion, double costoEstimado, double horasHombre,
                            double reduccionRiesgo) throws AuditoriaException {
        setIdAccion(idAccion);
        setActivo(activo);
        setVulnerabilidad(vulnerabilidad);
        setTipoAccion(tipoAccion);
        setCostoEstimado(costoEstimado);
        setHorasHombre(horasHombre);
        setReduccionRiesgo(reduccionRiesgo);
        this.aplicada = false;
    }

    public double calcularRatioCostoBeneficio() {
        return Math.round((reduccionRiesgo / costoEstimado) * 10000.0) / 10000.0;
    }

    public void aplicarParche() {
        if (!aplicada) {
            this.aplicada = true;
            if (activo != null && vulnerabilidad != null) {
                activo.removerVulnerabilidad(vulnerabilidad.getCodigoCVE());
            }
        }
    }

    public String getIdAccion() {
        return idAccion;
    }

    public void setIdAccion(String idAccion) throws AuditoriaException {
        this.idAccion = ValidadorDatos.validarTextoNoVacio(idAccion, "ID de Acción").toUpperCase();
    }

    public ActivoRed getActivo() {
        return activo;
    }

    public void setActivo(ActivoRed activo) throws AuditoriaException {
        if (activo == null) {
            throw new AuditoriaException("El activo objetivo de la acción no puede ser nulo.");
        }
        this.activo = activo;
    }

    public Vulnerabilidad getVulnerabilidad() {
        return vulnerabilidad;
    }

    public void setVulnerabilidad(Vulnerabilidad vulnerabilidad) throws AuditoriaException {
        if (vulnerabilidad == null) {
            throw new AuditoriaException("La vulnerabilidad objetivo de la acción no puede ser nula.");
        }
        this.vulnerabilidad = vulnerabilidad;
    }

    public String getTipoAccion() {
        return tipoAccion;
    }

    public void setTipoAccion(String tipoAccion) throws AuditoriaException {
        this.tipoAccion = ValidadorDatos.validarTextoNoVacio(tipoAccion, "Tipo de acción");
    }

    public double getCostoEstimado() {
        return costoEstimado;
    }

    public void setCostoEstimado(double costoEstimado) throws AuditoriaException {
        this.costoEstimado = ValidadorDatos.validarPositivo(costoEstimado, "Costo estimado");
    }

    public double getHorasHombre() {
        return horasHombre;
    }

    public void setHorasHombre(double horasHombre) throws AuditoriaException {
        this.horasHombre = ValidadorDatos.validarPositivo(horasHombre, "Horas hombre");
    }

    public double getReduccionRiesgo() {
        return reduccionRiesgo;
    }

    public void setReduccionRiesgo(double reduccionRiesgo) throws AuditoriaException {
        this.reduccionRiesgo = ValidadorDatos.validarPositivo(reduccionRiesgo, "Reducción de riesgo");
    }

    public boolean isAplicada() {
        return aplicada;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s en %s (%s) | Costo: $%.2f | Horas: %.1fh | Reducción: %.1f pts | Estado: %s",
                idAccion, tipoAccion, activo.getIdActivo(), vulnerabilidad.getCodigoCVE(),
                costoEstimado, horasHombre, reduccionRiesgo, aplicada ? "Aplicada" : "Pendiente");
    }
}
