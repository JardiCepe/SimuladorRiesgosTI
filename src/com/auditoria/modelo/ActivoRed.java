package com.auditoria.modelo;

import com.auditoria.util.AuditoriaException;
import com.auditoria.util.ValidadorDatos;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public abstract class ActivoRed {

    private String idActivo;
    private String direccionIP;
    private String hostname;
    private String sistemaOperativo;
    private String nivelExposicion;
    private final List<PuertoServicio> puertos;
    private final List<Vulnerabilidad> vulnerabilidades;

    protected ActivoRed(String idActivo, String direccionIP, String hostname, String sistemaOperativo)
            throws AuditoriaException {
        setIdActivo(idActivo);
        setDireccionIP(direccionIP);
        setHostname(hostname);
        setSistemaOperativo(sistemaOperativo);
        this.puertos = new ArrayList<>();
        this.vulnerabilidades = new ArrayList<>();
        this.nivelExposicion = "Baja";
    }

    // Agrega un puerto (composición) y actualiza automáticamente el nivel de exposición
    public void agregarPuerto(PuertoServicio p) throws AuditoriaException {
        if (p == null) {
            throw new AuditoriaException("El puerto de servicio no puede ser nulo.");
        }
        for (PuertoServicio existente : puertos) {
            if (existente.getNumeroPuerto() == p.getNumeroPuerto()
                    && existente.getProtocolo().equalsIgnoreCase(p.getProtocolo())) {
                throw new AuditoriaException(
                        "El puerto " + p.getNumeroPuerto() + "/" + p.getProtocolo()
                                + " ya está registrado en el activo " + idActivo + ".");
            }
        }
        puertos.add(p);
        evaluarExposicion();
    }

    public boolean removerPuerto(int numeroPuerto, String protocolo) throws AuditoriaException {
        String protoNorm = ValidadorDatos.validarProtocolo(protocolo);
        Iterator<PuertoServicio> it = puertos.iterator();
        while (it.hasNext()) {
            PuertoServicio p = it.next();
            if (p.getNumeroPuerto() == numeroPuerto && p.getProtocolo().equalsIgnoreCase(protoNorm)) {
                it.remove();
                evaluarExposicion();
                return true;
            }
        }
        return false;
    }

    // Clasifica el nivel de exposición del activo según sus puertos abiertos (RF1.2)
    public String evaluarExposicion() {
        if (puertos.isEmpty()) {
            this.nivelExposicion = "Baja";
            return this.nivelExposicion;
        }

        boolean tienePuertoCritico = false;
        boolean tienePuertoMedio = false;
        for (PuertoServicio puerto : puertos) {
            if (puerto.verificarRiesgoPuerto()) {
                tienePuertoCritico = true;
                break;
            }
            if ("MEDIA".equals(puerto.getNivelAlerta())) {
                tienePuertoMedio = true;
            }
        }

        if (tienePuertoCritico) {
            this.nivelExposicion = "Crítica";
        } else if (tienePuertoMedio || puertos.size() >= 3) {
            this.nivelExposicion = "Media";
        } else {
            this.nivelExposicion = "Baja";
        }
        return this.nivelExposicion;
    }

    public abstract double calcularFactorCriticidad();

    public abstract String getTipoActivo();

    // Calcula el puntaje CVSS consolidado (0.0 a 10.0) según vulnerabilidades y exposición
    public double getPuntajeCVSS() {
        if (vulnerabilidades.isEmpty()) {
            return 0.0;
        }
        double maxScore = 0.0;
        for (Vulnerabilidad v : vulnerabilidades) {
            double score = v.calcularScoreCVSS();
            if (score > maxScore) {
                maxScore = score;
            }
        }

        double adicional = 0.25 * (vulnerabilidades.size() - 1);
        double bonusExposicion = 0.0;
        String exp = evaluarExposicion();
        if ("Crítica".equals(exp)) {
            bonusExposicion = 0.7;
        } else if ("Media".equals(exp)) {
            bonusExposicion = 0.3;
        }

        double total = Math.min(10.0, maxScore + adicional + bonusExposicion);
        return Math.round(total * 10.0) / 10.0;
    }

    public void agregarVulnerabilidad(Vulnerabilidad v) throws AuditoriaException {
        if (v == null) {
            throw new AuditoriaException("La vulnerabilidad no puede ser nula.");
        }
        for (Vulnerabilidad existente : vulnerabilidades) {
            if (existente.getCodigoCVE().equalsIgnoreCase(v.getCodigoCVE())) {
                throw new AuditoriaException(
                        "La vulnerabilidad " + v.getCodigoCVE()
                                + " ya está asociada al activo " + idActivo + ".");
            }
        }
        vulnerabilidades.add(v);
    }

    public boolean removerVulnerabilidad(String codigoCVE) {
        if (codigoCVE == null) {
            return false;
        }
        String buscado = codigoCVE.trim();
        Iterator<Vulnerabilidad> it = vulnerabilidades.iterator();
        while (it.hasNext()) {
            if (it.next().getCodigoCVE().equalsIgnoreCase(buscado)) {
                it.remove();
                return true;
            }
        }
        return false;
    }

    public String getIdActivo() {
        return idActivo;
    }

    public void setIdActivo(String idActivo) throws AuditoriaException {
        this.idActivo = ValidadorDatos.validarTextoNoVacio(idActivo, "ID de Activo").toUpperCase();
    }

    public String getDireccionIP() {
        return direccionIP;
    }

    public void setDireccionIP(String direccionIP) throws AuditoriaException {
        this.direccionIP = ValidadorDatos.validarIPv4(direccionIP);
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) throws AuditoriaException {
        this.hostname = ValidadorDatos.validarTextoNoVacio(hostname, "Hostname");
    }

    public String getSistemaOperativo() {
        return sistemaOperativo;
    }

    public void setSistemaOperativo(String sistemaOperativo) throws AuditoriaException {
        this.sistemaOperativo = ValidadorDatos.validarTextoNoVacio(sistemaOperativo, "Sistema Operativo");
    }

    public String getNivelExposicion() {
        return nivelExposicion;
    }

    public List<PuertoServicio> getPuertos() {
        return new ArrayList<>(puertos);
    }

    public List<Vulnerabilidad> getVulnerabilidades() {
        return new ArrayList<>(vulnerabilidades);
    }

    @Override
    public String toString() {
        return String.format("[%s] %s (%s) - %s | SO: %s | Exp: %s | CVSS: %.1f",
                idActivo, hostname, direccionIP, getTipoActivo(),
                sistemaOperativo, nivelExposicion, getPuntajeCVSS());
    }
}
