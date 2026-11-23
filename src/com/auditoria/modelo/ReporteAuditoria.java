package com.auditoria.modelo;

import com.auditoria.util.AuditoriaException;
import com.auditoria.util.ValidadorDatos;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ReporteAuditoria {

    private String idAuditoria;
    private double umbralTolerancia;
    private double porcentajeCoberturaExigido;
    private LocalDate fechaValidez;
    private double scoreGlobal;
    private String dictamen;
    private final List<String> brechasPendientes;

    public ReporteAuditoria(String idAuditoria, double umbralTolerancia,
                            double porcentajeCoberturaExigido, LocalDate fechaValidez)
            throws AuditoriaException {
        setIdAuditoria(idAuditoria);
        setUmbralTolerancia(umbralTolerancia);
        setPorcentajeCoberturaExigido(porcentajeCoberturaExigido);
        setFechaValidez(fechaValidez);
        this.scoreGlobal = 0.0;
        this.brechasPendientes = new ArrayList<>();
        this.dictamen = "No Conforme";
    }

    public String emitirDictamen() {
        if (scoreGlobal >= 80.0 && brechasPendientes.isEmpty()) {
            this.dictamen = "Aceptable";
        } else if (scoreGlobal >= 55.0) {
            this.dictamen = "Riesgo Moderado";
        } else {
            this.dictamen = "No Conforme";
        }
        return this.dictamen;
    }

    public List<String> listarBrechasPendientes() {
        return Collections.unmodifiableList(brechasPendientes);
    }

    public void actualizarResultados(double scoreGlobal, List<String> brechas) throws AuditoriaException {
        this.scoreGlobal = ValidadorDatos.validarRango(scoreGlobal, 0.0, 100.0, "Score Global");
        this.brechasPendientes.clear();
        if (brechas != null) {
            this.brechasPendientes.addAll(brechas);
        }
        emitirDictamen();
    }

    public String getIdAuditoria() {
        return idAuditoria;
    }

    public void setIdAuditoria(String idAuditoria) throws AuditoriaException {
        this.idAuditoria = ValidadorDatos.validarTextoNoVacio(idAuditoria, "ID de Auditoría").toUpperCase();
    }

    public double getUmbralTolerancia() {
        return umbralTolerancia;
    }

    public void setUmbralTolerancia(double umbralTolerancia) throws AuditoriaException {
        this.umbralTolerancia = ValidadorDatos.validarRango(
                umbralTolerancia, 0.0, 10.0, "Umbral de tolerancia CVSS");
    }

    public double getPorcentajeCoberturaExigido() {
        return porcentajeCoberturaExigido;
    }

    public void setPorcentajeCoberturaExigido(double porcentajeCoberturaExigido) throws AuditoriaException {
        this.porcentajeCoberturaExigido = ValidadorDatos.validarRango(
                porcentajeCoberturaExigido, 0.0, 100.0, "Porcentaje de cobertura exigido");
    }

    public LocalDate getFechaValidez() {
        return fechaValidez;
    }

    public void setFechaValidez(LocalDate fechaValidez) throws AuditoriaException {
        if (fechaValidez == null) {
            throw new AuditoriaException("La fecha de validez no puede ser nula.");
        }
        this.fechaValidez = fechaValidez;
    }

    public double getScoreGlobal() {
        return scoreGlobal;
    }

    public String getDictamen() {
        return dictamen;
    }
}
