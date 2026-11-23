package com.auditoria.modelo;

import com.auditoria.util.AuditoriaException;
import com.auditoria.util.ValidadorDatos;

public class Vulnerabilidad {

    private String codigoCVE;
    private String descripcion;
    private String soAfectado;
    private int puertoAsociado;
    private String vectorAtaque;
    private double[] impactoCIA;
    private double puntajeCVSS;

    public Vulnerabilidad(String codigoCVE, String descripcion, String soAfectado,
                          int puertoAsociado, String vectorAtaque, double[] impactoCIA)
            throws AuditoriaException {
        setCodigoCVE(codigoCVE);
        setDescripcion(descripcion);
        setSoAfectado(soAfectado);
        setPuertoAsociado(puertoAsociado);
        setVectorAtaque(vectorAtaque);
        setImpactoCIA(impactoCIA);
        calcularScoreCVSS();
    }

    public double calcularScoreCVSS() {
        double c = impactoCIA[0];
        double i = impactoCIA[1];
        double a = impactoCIA[2];

        double iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
        if (iss <= 0.0) {
            this.puntajeCVSS = 0.0;
            return this.puntajeCVSS;
        }

        double impacto = 6.42 * iss;
        // Vector Remoto equivale a AV:N (0.85), PR:N (0.85); Local equivale a AV:L (0.55), PR:L (0.62)
        double av = "Remoto".equalsIgnoreCase(vectorAtaque) ? 0.85 : 0.55;
        double pr = "Remoto".equalsIgnoreCase(vectorAtaque) ? 0.85 : 0.62;
        double ac = 0.77;
        double ui = 0.85;
        double explotabilidad = 8.22 * av * ac * pr * ui;

        double base = Math.min(10.0, impacto + explotabilidad);
        // Redondeo hacia arriba a 1 decimal según convención CVSS v3.1
        this.puntajeCVSS = Math.min(10.0, Math.ceil(base * 10.0) / 10.0);
        return this.puntajeCVSS;
    }

    public String obtenerEtiquetaSeveridad() {
        double score = calcularScoreCVSS();
        if (score == 0.0) {
            return "Informativo";
        }
        if (score < 4.0) {
            return "Bajo";
        }
        if (score < 7.0) {
            return "Medio";
        }
        if (score < 9.0) {
            return "Alto";
        }
        return "Crítico";
    }

    public String getCodigoCVE() {
        return codigoCVE;
    }

    public void setCodigoCVE(String codigoCVE) throws AuditoriaException {
        this.codigoCVE = ValidadorDatos.validarCodigoCVE(codigoCVE);
    }

    public String getDescripcion() {
        return descripcion;
    }

    public void setDescripcion(String descripcion) throws AuditoriaException {
        this.descripcion = ValidadorDatos.validarTextoNoVacio(descripcion, "Descripción");
    }

    public String getSoAfectado() {
        return soAfectado;
    }

    public void setSoAfectado(String soAfectado) throws AuditoriaException {
        this.soAfectado = ValidadorDatos.validarTextoNoVacio(soAfectado, "SO afectado");
    }

    public int getPuertoAsociado() {
        return puertoAsociado;
    }

    public void setPuertoAsociado(int puertoAsociado) throws AuditoriaException {
        this.puertoAsociado = ValidadorDatos.validarPuertoOpcional(puertoAsociado);
    }

    public String getVectorAtaque() {
        return vectorAtaque;
    }

    public void setVectorAtaque(String vectorAtaque) throws AuditoriaException {
        this.vectorAtaque = ValidadorDatos.validarVectorAtaque(vectorAtaque);
        if (this.impactoCIA != null) {
            calcularScoreCVSS();
        }
    }

    public double[] getImpactoCIA() {
        return impactoCIA.clone();
    }

    public void setImpactoCIA(double[] impactoCIA) throws AuditoriaException {
        if (impactoCIA == null || impactoCIA.length != 3) {
            throw new AuditoriaException(
                    "El arreglo impactoCIA debe tener exactamente 3 métricas: [Confidencialidad, Integridad, Disponibilidad].");
        }
        double[] copia = new double[3];
        String[] nombres = {"Confidencialidad", "Integridad", "Disponibilidad"};
        for (int idx = 0; idx < 3; idx++) {
            copia[idx] = ValidadorDatos.validarRango(impactoCIA[idx], 0.0, 1.0, nombres[idx]);
        }
        this.impactoCIA = copia;
        calcularScoreCVSS();
    }

    public double getPuntajeCVSS() {
        return puntajeCVSS;
    }

    @Override
    public String toString() {
        return String.format("%s - %s [CVSS: %.1f (%s), Vector: %s]",
                codigoCVE, descripcion, puntajeCVSS, obtenerEtiquetaSeveridad(), vectorAtaque);
    }
}
